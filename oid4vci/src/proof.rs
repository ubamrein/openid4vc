use oid4vc_core::{builder_fn, jwt, RFC7519Claims, Subject};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Key Proof Type (JWT or CWT) and the proof itself, as described here: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-13.html#proof-types
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(tag = "proof_type")]
pub enum KeyProofType {
    #[serde(rename = "jwt")]
    Jwt { jwt: String },
    #[serde(rename = "cwt")]
    Cwt { cwt: String },
    #[serde(rename = "attestation")]
    Attestation { attestation: String },
}

impl KeyProofType {
    pub fn builder() -> ProofBuilder {
        ProofBuilder::default()
    }
}

// Key Proof_s_ type for multiple proof-of-posessions in the same credential request
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(rename_all = "lowercase")]
pub enum KeyProofsType {
    Jwt(Vec<String>),
    Cwt(Vec<String>)
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct KeyProofMetadata {
    pub proof_signing_alg_values_supported: Vec<String>,
    pub key_attestations_required: Option<KeyAttestationMetadata>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct KeyAttestationMetadata {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub key_storage: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub user_authentication: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum ProofType {
    Jwt,
    Cwt,
    // TODO: add support for `LdpVp` as described here: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-13.html#section-7.2.1-2.3
}

#[derive(Default)]
pub struct ProofBuilder {
    proof_type: Option<ProofType>,
    rfc7519_claims: RFC7519Claims,
    nonce: Option<String>,
    signer: Option<Arc<dyn Subject>>,
    subject_syntax_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProofOfPossession {
    #[serde(flatten)]
    pub rfc7519_claims: RFC7519Claims,
    pub nonce: String,
}

impl ProofBuilder {
    pub async fn build_no_sign(self) -> anyhow::Result<KeyProofType> {
        anyhow::ensure!(self.rfc7519_claims.aud.is_some(), "aud claim is required");
        anyhow::ensure!(self.rfc7519_claims.iat.is_some(), "iat claim is required");
        anyhow::ensure!(self.nonce.is_some(), "nonce claim is required");

        let subject_syntax_type = self
            .subject_syntax_type
            .ok_or(anyhow::anyhow!("subject_syntax_type is required"))?;

        match self.proof_type {
            Some(ProofType::Jwt) => Ok(KeyProofType::Jwt {
                jwt: jwt::encode_body(
                    self.signer.as_ref().ok_or(anyhow::anyhow!("No subject found"))?.clone(),
                    self.signer
                        .ok_or(anyhow::anyhow!("No subject found"))?
                        .jwt_header()
                        .await,
                    ProofOfPossession {
                        rfc7519_claims: self.rfc7519_claims,
                        nonce: self.nonce.ok_or(anyhow::anyhow!("No nonce found"))?,
                    },
                    &subject_syntax_type,
                    false,
                )
                .await?,
            }),
            Some(ProofType::Cwt) => todo!(),
            None => Err(anyhow::anyhow!("proof_type is required")),
        }
    }
    pub async fn build(self) -> anyhow::Result<KeyProofType> {
        anyhow::ensure!(self.rfc7519_claims.aud.is_some(), "aud claim is required");
        anyhow::ensure!(self.rfc7519_claims.iat.is_some(), "iat claim is required");
        anyhow::ensure!(self.nonce.is_some(), "nonce claim is required");

        let subject_syntax_type = self
            .subject_syntax_type
            .ok_or(anyhow::anyhow!("subject_syntax_type is required"))?;

        match self.proof_type {
            Some(ProofType::Jwt) => Ok(KeyProofType::Jwt {
                jwt: jwt::encode(
                    self.signer.as_ref().ok_or(anyhow::anyhow!("No subject found"))?.clone(),
                    self.signer
                        .ok_or(anyhow::anyhow!("No subject found"))?
                        .jwt_header()
                        .await,
                    ProofOfPossession {
                        rfc7519_claims: self.rfc7519_claims,
                        nonce: self.nonce.ok_or(anyhow::anyhow!("No nonce found"))?,
                    },
                    &subject_syntax_type,
                    false,
                )
                .await?,
            }),
            Some(ProofType::Cwt) => todo!(),
            None => Err(anyhow::anyhow!("proof_type is required")),
        }
    }

    pub fn signer(mut self, signer: Arc<dyn Subject>) -> Self {
        self.signer = Some(signer);
        self
    }

    builder_fn!(proof_type, ProofType);
    builder_fn!(rfc7519_claims, iss, String);
    builder_fn!(rfc7519_claims, aud, String);
    // TODO: fix this, required by jsonwebtoken crate.
    builder_fn!(rfc7519_claims, exp, i64);
    builder_fn!(rfc7519_claims, iat, i64);
    builder_fn!(nonce, String);
    builder_fn!(subject_syntax_type, String);
}
