use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::authorization_details::AuthorizationDetailsObject;
use crate::authorization_request::{AuthorizationRequest, PushedAuthorizationRequest};
use crate::authorization_response::AuthorizationResponse;
use crate::credential_format_profiles::{CredentialFormatCollection, CredentialFormats, WithParameters};
use crate::credential_issuer::{
    authorization_server_metadata::AuthorizationServerMetadata, credential_issuer_metadata::CredentialIssuerMetadata,
};
use crate::credential_offer::{AuthorizationRequestReference, CredentialOfferParameters};
use crate::credential_request::{CredentialRequest, OneOrManyKeyProofs};
use crate::credential_response::CredentialResponseType;
use crate::proof::{KeyProofType, KeyProofsType, ProofType};
use crate::wallet::content_encryption::ContentDecryptor;
use crate::{credential_response::CredentialResponse, token_request::TokenRequest, token_response::TokenResponse};
use anyhow::{bail, Result};
use oid4vc_core::authentication::subject::SigningSubject;
use oid4vc_core::SubjectSyntaxType;
use reqwest::Url;
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use reqwest_retry::policies::ExponentialBackoff;
use reqwest_retry::RetryTransientMiddleware;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};
use OneOrManyKeyProofs::{Proof, Proofs};

pub mod content_encryption;

pub struct Wallet<CFC = CredentialFormats<WithParameters>>
where
    CFC: CredentialFormatCollection,
{
    pub subjects: Vec<SigningSubject>,
    pub default_subject_syntax_type: SubjectSyntaxType,
    pub client: ClientWithMiddleware,
    phantom: std::marker::PhantomData<CFC>,
}

impl<CFC: CredentialFormatCollection + DeserializeOwned> Wallet<CFC> {
    pub fn new(
        subjects: Vec<SigningSubject>,
        default_subject_syntax_type: impl TryInto<SubjectSyntaxType>,
    ) -> anyhow::Result<Self> {
        let retry_policy = ExponentialBackoff::builder().build_with_max_retries(5);
        let client = ClientBuilder::new(reqwest::Client::new())
            .with(RetryTransientMiddleware::new_with_policy(retry_policy))
            .build();
        Ok(Self {
            subjects,
            default_subject_syntax_type: default_subject_syntax_type
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid did method"))?,
            client,
            phantom: std::marker::PhantomData,
        })
    }

    pub async fn push_authorization_request(
        &self,
        par_endpoint: Url,
        auth_request: PushedAuthorizationRequest,
    ) -> Result<AuthorizationRequestReference> {
        self.client
            .post(par_endpoint)
            .form(&auth_request)
            .send()
            .await
            .map_err(|e| {
                println!("--> {e}");
                e
            })?
            .error_for_status_detailed()
            .await
            .map_err(|e| {
                println!("--> {e}");
                e
            })?
            .json()
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))
    }

    pub async fn get_credential_offer(&self, credential_offer_uri: Url) -> Result<CredentialOfferParameters> {
        self.client
            .get(credential_offer_uri)
            .send()
            .await?
            .error_for_status_detailed()
            .await?
            .json::<CredentialOfferParameters>()
            .await
            .map_err(|_| anyhow::anyhow!("Failed to get credential offer"))
    }

    pub async fn get_authorization_server_metadata(
        &self,
        credential_issuer_url: Url,
    ) -> Result<AuthorizationServerMetadata> {
        let mut oauth_authorization_server_endpoint = credential_issuer_url.clone();
        let mut oidc_authorization_server_endpoint = credential_issuer_url.clone();
        // TODO(NGDIL): remove this NGDIL specific code. This is a temporary fix to get the authorization server metadata.
        oauth_authorization_server_endpoint
            .path_segments_mut()
            .map_err(|_| anyhow::anyhow!("unable to parse credential issuer url"))
            .unwrap()
            .push(".well-known")
            .push("oauth-authorization-server");
        oidc_authorization_server_endpoint
            .path_segments_mut()
            .map_err(|_| anyhow::anyhow!("unable to parse credential issuer url"))
            .unwrap()
            .push(".well-known")
            .push("openid-configuration");
        let response = self
            .client
            .get(oidc_authorization_server_endpoint.clone())
            .send()
            .await?;
        // Try oidc first, then oauth as fallback. Report both errors if neither works.
        let res_oidc = match response.error_for_status() {
            // Note: and_then does not work with async
            Ok(response) => response.json::<AuthorizationServerMetadata>().await,
            Err(e) => Err(e),
        };
        match res_oidc {
            Ok(res) => Ok(res),
            Err(err_oidc) => {
                // try oauth next
                let response = self
                    .client
                    .get(oauth_authorization_server_endpoint.clone())
                    .send()
                    .await?;
                let res_oauth = match response.error_for_status() {
                    Ok(response) => response.json::<AuthorizationServerMetadata>().await,
                    Err(e) => Err(e),
                };
                match res_oauth {
                    Ok(res) => Ok(res),
                    Err(err_oauth) => Err(anyhow::anyhow!(
                        "Failed to get authorization server metadata\n\
                                             [oidc]: {err_oidc} ({oidc_authorization_server_endpoint})\n\
                                             [oauth]: {err_oauth} ({oauth_authorization_server_endpoint})"
                    )),
                }
            }
        }
    }

    pub async fn get_credential_issuer_metadata(
        &self,
        credential_issuer_url: Url,
    ) -> Result<CredentialIssuerMetadata<CFC>> {
        let mut openid_credential_issuer_endpoint = credential_issuer_url.clone();

        // TODO(NGDIL): remove this NGDIL specific code. This is a temporary fix to get the credential issuer metadata.
        openid_credential_issuer_endpoint
            .path_segments_mut()
            .map_err(|_| anyhow::anyhow!("unable to parse credential issuer url"))?
            .push(".well-known")
            .push("openid-credential-issuer");

        Ok(self
            .client
            .get(openid_credential_issuer_endpoint)
            .send()
            .await?
            .error_for_status()?
            .json::<CredentialIssuerMetadata<CFC>>()
            .await
            .unwrap())
        // .map_err(|_| anyhow::anyhow!("Failed to get credential issuer metadata"))
    }

    pub async fn get_authorization_code(
        &self,
        authorization_endpoint: Url,
        authorization_details: Vec<AuthorizationDetailsObject<CFC>>,
    ) -> Result<AuthorizationResponse> {
        self.client
            .get(authorization_endpoint)
            // TODO: must be `form`, but `AuthorizationRequest needs to be able to serilalize properly.
            .json(&AuthorizationRequest {
                response_type: "code".to_string(),
                client_id: self
                    .subjects
                    .first()
                    .unwrap()
                    .identifier(&self.default_subject_syntax_type.to_string())
                    .await?,
                redirect_uri: None,
                scope: None,
                state: None,
                authorization_details,
            })
            .send()
            .await?
            .error_for_status_detailed()
            .await?
            .json::<AuthorizationResponse>()
            .await
            .map_err(|_| anyhow::anyhow!("Failed to get authorization code"))
    }

    pub async fn get_access_token(&self, token_endpoint: Url, token_request: TokenRequest) -> Result<TokenResponse> {
        self.client
            .post(token_endpoint)
            .form(&token_request)
            .send()
            .await?
            .error_for_status_detailed()
            .await?
            .json()
            .await
            .map_err(|e| e.into())
    }

    pub async fn try_get_deferred_credential(
        &self,
        credential_issuer_metadata: CredentialIssuerMetadata<CFC>,
        token_response: &TokenResponse,
        credential_response: CredentialResponse,
    ) -> Result<CredentialResponse> {
        let CredentialResponseType::Deferred { transaction_id } = credential_response.credential else {
            bail!("not a deferred credential");
        };
        let Some(deferred_endpoint) = credential_issuer_metadata.deferred_credential_endpoint.as_ref() else {
            bail!("deferred credentials not  supported by remote");
        };
        let mut map = Map::new();
        map.insert("transaction_id".to_string(), Value::String(transaction_id));
        let transaction_id: Value = Value::Object(map);
        self.client
            .post(deferred_endpoint.to_owned())
            .bearer_auth(token_response.access_token.clone())
            .json(&transaction_id)
            .send()
            .await?
            .error_for_status_detailed()
            .await?
            .json::<CredentialResponse>()
            .await
            .map_err(|e| e.into())
    }

    pub async fn get_credential_with_proofs(
        &self,
        credential_issuer_metadata: CredentialIssuerMetadata<CFC>,
        access_token: String,
        credential_configuration_id: String,
        // For backwards compatibility with pre-draft15 only. Remove.
        credential_format: CFC,
        content_decryptor: Option<Box<dyn ContentDecryptor>>,
        proofs: OneOrManyKeyProofs,
    ) -> Result<CredentialResponse> {
        let credential_response_encryption = if let Some(content_decryptor) = content_decryptor.as_ref() {
            Some(content_decryptor.encryption_specification())
        } else {
            None
        };

        // convert to single "proof" instead of "proofs" if possible
        let proofs = if let Proofs(KeyProofsType::Jwt(jwts)) = &proofs {
            if jwts.len() == 1 {
                Proof(jwts.first().map(|jwt| KeyProofType::Jwt { jwt: jwt.clone() }))
            } else {
                proofs
            }
        } else {
            proofs
        };

        // Backwards compatibility hack to only send appropriate fields in request:
        // No surefire way to find out which version, but draft 15 compatible issuer will very
        // likely have a nonce endpoint.
        let is_openid4vci_draft15_issuer = credential_issuer_metadata.nonce_endpoint.is_some();
        let credential_request = if is_openid4vci_draft15_issuer {
            CredentialRequest {
                credential_configuration_id: Some(credential_configuration_id),
                credential_format: None,
                proof: proofs,
                credential_response_encryption: credential_response_encryption.clone(),
            }
        } else {
            CredentialRequest {
                credential_configuration_id: None,
                credential_format: Some(credential_format),
                proof: proofs,
                credential_response_encryption: credential_response_encryption.clone(),
            }
        };

        let response = self
            .client
            .post(credential_issuer_metadata.credential_endpoint.clone())
            .bearer_auth(access_token.clone())
            .json(&credential_request)
            .send()
            .await?
            .error_for_status_detailed()
            .await?;
        let text = response.text().await?;
        println!("{text}");
        serde_json::from_str(&text).map_err(|e| e.into())
    }

    pub async fn get_proof_body(
        &self,
        credential_issuer_metadata: CredentialIssuerMetadata<CFC>,
        c_nonce: Option<String>,
        client_id: &str,
    ) -> Result<Vec<String>> {
        let nonce = c_nonce.as_ref().ok_or(anyhow::anyhow!("No c_nonce found."))?; // XXX
        let timestamp = SystemTime::now();
        let timestamp = timestamp.duration_since(UNIX_EPOCH).expect("Time went backwards");
        let mut proofs = vec![];
        for subject in &self.subjects {
            let Ok(kpt) = KeyProofType::builder()
                .proof_type(ProofType::Jwt)
                .signer(subject.clone())
                .iss(client_id)
                .aud(credential_issuer_metadata.credential_issuer.clone())
                .iat(timestamp.as_secs() as i64)
                .exp((timestamp + Duration::from_secs(360)).as_secs() as i64)
                .nonce(nonce.clone())
                .subject_syntax_type(self.default_subject_syntax_type.to_string())
                .build_no_sign()
                .await
            else {
                continue;
            };
            if let KeyProofType::Jwt { jwt } = kpt {
                proofs.push(jwt);
            }
        }
        Ok(proofs)
    }

    pub async fn get_credential(
        &self,
        credential_issuer_metadata: CredentialIssuerMetadata<CFC>,
        access_token: String,
        c_nonce: Option<String>,
        // For backwards compatibility with pre-draft15 only. Remove.
        credential_configuration_id: String,
        credential_format: CFC,
        content_decryptor: Option<Box<dyn ContentDecryptor>>,
        client_id: &str,
    ) -> Result<CredentialResponse> {
        let timestamp = SystemTime::now();
        let timestamp = timestamp.duration_since(UNIX_EPOCH).expect("Time went backwards");

        let mut proofs = vec![];
        for subject in &self.subjects {
            let mut kpb = KeyProofType::builder()
                .proof_type(ProofType::Jwt)
                .signer(subject.clone())
                .iss(client_id)
                .aud(credential_issuer_metadata.credential_issuer.clone())
                .iat(timestamp.as_secs() as i64)
                .exp((timestamp + Duration::from_secs(360)).as_secs() as i64)
                .subject_syntax_type(self.default_subject_syntax_type.to_string());
            if let Some(nonce) = &c_nonce {
                kpb = kpb.nonce(nonce);
            }
            let Ok(kpt) = kpb.build().await else {
                continue;
            };
            if let KeyProofType::Jwt { jwt } = kpt {
                proofs.push(jwt);
            }
        }
        self.get_credential_with_proofs(
            credential_issuer_metadata,
            access_token,
            credential_configuration_id,
            credential_format,
            content_decryptor,
            Proofs(KeyProofsType::Jwt(proofs)),
        )
        .await
    }
}

use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ErrorDetails {
    #[serde(skip_serializing, skip_deserializing)]
    pub status: reqwest::StatusCode,
    pub error: String,
    #[serde(alias = "description")]
    pub error_description: String,
}

impl std::fmt::Display for ErrorDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "status: {}, error: \"{}\", error description: \"{}\"",
            self.status, self.error, self.error_description
        )
    }
}

impl std::error::Error for ErrorDetails {}

// Like reqwest.Response.error_for_status, but includes the details of the error returned by the
// server, if they can be parsed.
trait ErrorForStatusDetailed
where
    Self: std::marker::Sized,
{
    async fn error_for_status_detailed(self) -> Result<Self>;
}

impl ErrorForStatusDetailed for reqwest::Response {
    async fn error_for_status_detailed(self) -> Result<Self> {
        if let Err(err_status) = self.error_for_status_ref() {
            let status = self.status();
            if status.is_client_error() {
                match self.json::<ErrorDetails>().await {
                    Ok(details) => Err(ErrorDetails {
                        status,
                        error: details.error,
                        error_description: details.error_description,
                    }
                    .into()),
                    Err(_) => Err(err_status.into()),
                }
            } else {
                Err(err_status.into())
            }
        } else {
            Ok(self)
        }
    }
}
