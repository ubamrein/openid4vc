use crate::{
    authorization_details::AuthorizationDetailsObject, credential_format_profiles::CredentialFormatCollection,
};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

/// The Authorization Request is used to request authorization as described here: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-13.html#name-authorization-request
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorizationRequest<CFC>
where
    CFC: CredentialFormatCollection,
{
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub authorization_details: Vec<AuthorizationDetailsObject<CFC>>,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
pub struct PushedAuthorizationRequest {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>
}
