use crate::authorization_details::AuthorizationDetailsObject;
use crate::authorization_request::{AuthorizationRequest, PushedAuthorizationRequest};
use crate::authorization_response::AuthorizationResponse;
use crate::credential_format_profiles::{CredentialFormatCollection, CredentialFormats, WithParameters};
use crate::credential_issuer::{
    authorization_server_metadata::AuthorizationServerMetadata, credential_issuer_metadata::CredentialIssuerMetadata,
};
use crate::credential_offer::{AuthorizationRequestReference, CredentialOfferParameters};
use crate::credential_request::{
    BatchCredentialRequest, CredentialRequest, CredentialResponseEncryptionKey,
    CredentialResponseEncryptionSpecification,
};
use crate::credential_response::{BatchCredentialResponse, CredentialResponseType};
use crate::proof::{KeyProofType, ProofType};
use crate::{credential_response::CredentialResponse, token_request::TokenRequest, token_response::TokenResponse};
use anyhow::{bail, Result};
use base64::Engine;
use jsonwebtoken::jwk::{CommonParameters, Jwk, RSAKeyParameters};
use libaes::Cipher;
use oid4vc_core::authentication::subject::SigningSubject;
use oid4vc_core::jwt::{base64_url_decode, base64_url_encode};
use oid4vc_core::SubjectSyntaxType;
use reqwest::Url;
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use reqwest_retry::policies::ExponentialBackoff;
use reqwest_retry::RetryTransientMiddleware;
use rsa::rand_core::OsRng;
use rsa::traits::PublicKeyParts;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};
use sha1::Sha1;
use sha2::Sha256;
use crate::wallet::content_encryption::ContentDecryptor;

pub mod content_encryption;

pub struct Wallet<CFC = CredentialFormats<WithParameters>>
    where
        CFC: CredentialFormatCollection,
{
    pub subject: SigningSubject,
    pub default_subject_syntax_type: SubjectSyntaxType,
    pub client: ClientWithMiddleware,
    phantom: std::marker::PhantomData<CFC>,
}

impl<CFC: CredentialFormatCollection + DeserializeOwned> Wallet<CFC> {
    pub fn new(
        subject: SigningSubject,
        default_subject_syntax_type: impl TryInto<SubjectSyntaxType>,
    ) -> anyhow::Result<Self> {
        let retry_policy = ExponentialBackoff::builder().build_with_max_retries(5);
        let client = ClientBuilder::new(reqwest::Client::new())
            .with(RetryTransientMiddleware::new_with_policy(retry_policy))
            .build();
        Ok(Self {
            subject,
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
            .await?
            .json()
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))
    }

    pub async fn get_credential_offer(&self, credential_offer_uri: Url) -> Result<CredentialOfferParameters> {
        self.client
            .get(credential_offer_uri)
            .send()
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

        if let Ok(result) = self.client.get(oidc_authorization_server_endpoint).send().await {
            result
                .json::<AuthorizationServerMetadata>()
                .await
                .map_err(|_| anyhow::anyhow!("Failed to get authorization server metadata [oidc]"))
        } else {
            self.client
                .get(oauth_authorization_server_endpoint)
                .send()
                .await?
                .json::<AuthorizationServerMetadata>()
                .await
                .map_err(|_| anyhow::anyhow!("Failed to get authorization server metadata [oauth]"))
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
                    .subject
                    .identifier(&self.default_subject_syntax_type.to_string())
                    .await?,
                redirect_uri: None,
                scope: None,
                state: None,
                authorization_details,
            })
            .send()
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
            .json::<CredentialResponse>()
            .await
            .map_err(|e| e.into())
    }

    //TODO: make encryption/decryption abstract and ooptional
    pub async fn get_credential(
        &self,
        credential_issuer_metadata: CredentialIssuerMetadata<CFC>,
        token_response: &TokenResponse,
        credential_format: CFC,
        content_decryptor: Option<Box<dyn ContentDecryptor>>,
    ) -> Result<CredentialResponse> {
        let retry_with_proof = token_response.c_nonce.is_none();
        let proof = if token_response.c_nonce.is_some() {
            Some(
                KeyProofType::builder()
                    .proof_type(ProofType::Jwt)
                    .signer(self.subject.clone())
                    .iss(
                        self.subject
                            .identifier(&self.default_subject_syntax_type.to_string())
                            .await?,
                    )
                    .aud(credential_issuer_metadata.credential_issuer.clone())
                    .iat(1571324800)
                    .exp(9999999999i64)
                    // TODO: so is this REQUIRED or OPTIONAL?
                    .nonce(
                        token_response
                            .c_nonce
                            .as_ref()
                            .ok_or(anyhow::anyhow!("No c_nonce found."))?
                            .clone(),
                    )
                    .subject_syntax_type(self.default_subject_syntax_type.to_string())
                    .build()
                    .await?,
            )
        } else {
            None
        };
        let credential_response_encryption = if let Some(content_decryptor) = content_decryptor.as_ref() {
            Some(content_decryptor.encryption_specification())
        } else {
            None
        };
        let credential_request = CredentialRequest {
            credential_format: credential_format.clone(),
            proof,
            credential_response_encryption: credential_response_encryption.clone(),
        };

        if retry_with_proof {
            let mut response = self
                .client
                .post(credential_issuer_metadata.credential_endpoint.clone())
                .bearer_auth(token_response.access_token.clone())
                .json(&credential_request)
                .send()
                .await?
                .text()
                .await?;
            let response_value = serde_json::from_str::<Value>(&response);
            // it is no json, so try to decrypt
            if response_value.is_err() {
                if let Some(content_decryptor) = content_decryptor.as_ref() {
                    let Ok(decrypted_response) = content_decryptor.decrypt(&response) else {
                        bail!("Could not decrypt content");
                    };
                    let Ok(decrypted_json) = std::str::from_utf8(&decrypted_response) else {
                        bail!("Decrypted content is not valid utf8");
                    };
                    response = decrypted_json.to_string();
                } else {
                    bail!("Content is probably encrypted");
                }
            }
            match serde_json::from_str::<CredentialResponse>(&response) {
                Ok(resp) => return Ok(resp),
                Err(_) => {}
            }
            let response = response_value.unwrap();
            let c_nonce = response.get("c_nonce").unwrap().as_str().unwrap();

            println!("using c_nonce --> {c_nonce}");

            let proof = Some(
                KeyProofType::builder()
                    .proof_type(ProofType::Jwt)
                    .signer(self.subject.clone())
                    .iss(
                        self.subject
                            .identifier(&self.default_subject_syntax_type.to_string())
                            .await?,
                    )
                    .aud(credential_issuer_metadata.credential_issuer)
                    .iat(1571324800)
                    .exp(9999999999i64)
                    // TODO: so is this REQUIRED or OPTIONAL?
                    .nonce(c_nonce.to_string())
                    .subject_syntax_type(self.default_subject_syntax_type.to_string())
                    .build()
                    .await?,
            );

            let credential_request = CredentialRequest {
                credential_format: credential_format.clone(),
                proof,
                credential_response_encryption: credential_response_encryption.clone(),
            };
            let Ok(response) = self
                .client
                .post(credential_issuer_metadata.credential_endpoint.clone())
                .bearer_auth(token_response.access_token.clone())
                .json(&credential_request)
                .send()
                .await?
                .text()
                .await
                else {
                    bail!("failure retrieveing stuff");
                };

            match serde_json::from_str::<CredentialResponse>(&response) {
                Ok(resp) =>  Ok(resp),
                Err(_) if content_decryptor.is_some() => {
                    // let's try to decrypt (we checked for is_some so this is valid, workaround until we have let guards)
                    let content_decryptor = content_decryptor.as_ref().unwrap();
                    let decyrpted_content = match content_decryptor.decrypt(&response) {
                        Ok(content) => content,
                        Err(e) => return Err(anyhow::anyhow!(e))
                    };
                    serde_json::from_slice(&decyrpted_content).map_err(|e| anyhow::anyhow!(e))
                }
                _ => bail!("Content is probably encrypted")
            }
        } else {
            self.client
                .post(credential_issuer_metadata.credential_endpoint.clone())
                .bearer_auth(token_response.access_token.clone())
                .json(&credential_request)
                .send()
                .await?
                .json()
                .await
                .map_err(|e| e.into())
        }
    }

    pub async fn get_batch_credential(
        &self,
        credential_issuer_metadata: CredentialIssuerMetadata<CFC>,
        token_response: &TokenResponse,
        credential_formats: Vec<CFC>,
    ) -> Result<BatchCredentialResponse> {
        let privatekey = rsa::RsaPrivateKey::new(&mut OsRng, 2028).unwrap();
        let pub_key = serde_json::to_value(privatekey.to_public_key()).unwrap();

        let jwk = CredentialResponseEncryptionKey::Rsa {
            alg: "RSA-OAEP-256".to_string(),
            n: pub_key.get("n").unwrap().as_str().unwrap().to_string(),
            e: pub_key.get("e").unwrap().as_str().unwrap().to_string(),
            kid: "rsa-key".to_string(),
            r#use: "enc".to_string(),
            kty: "RSA".to_string(),
        };
        let encryption_spec = CredentialResponseEncryptionSpecification {
            jwk,
            enc: "A128CBC-HS256".to_string(),
            alg: "RSA-OAEP-256".to_string(),
        };
        let proof = Some(
            KeyProofType::builder()
                .proof_type(ProofType::Jwt)
                .signer(self.subject.clone())
                .iss(
                    self.subject
                        .identifier(&self.default_subject_syntax_type.to_string())
                        .await?,
                )
                .aud(credential_issuer_metadata.credential_issuer)
                .iat(1571324800)
                .exp(9999999999i64)
                // TODO: so is this REQUIRED or OPTIONAL?
                .nonce(
                    token_response
                        .c_nonce
                        .as_ref()
                        .ok_or(anyhow::anyhow!("No c_nonce found."))?
                        .clone(),
                )
                .subject_syntax_type(self.default_subject_syntax_type.to_string())
                .build()
                .await?,
        );

        let batch_credential_request = BatchCredentialRequest {
            credential_requests: credential_formats
                .iter()
                .map(|credential_format| CredentialRequest {
                    credential_format: credential_format.to_owned(),
                    proof: proof.clone(),
                    credential_response_encryption: Some(encryption_spec.clone()),
                })
                .collect(),
        };

        self.client
            .post(credential_issuer_metadata.batch_credential_endpoint.unwrap())
            .bearer_auth(token_response.access_token.clone())
            .json(&batch_credential_request)
            .send()
            .await?
            .json()
            .await
            .map_err(|e| e.into())
    }
}
