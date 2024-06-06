use crate::credential_format;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use super::CredentialSubject;

credential_format!("jwt_vc_json", JwtVcJson, {
    credential_definition: CredentialDefinition,
    order: Option<String>
});
credential_format!("vc+sd-jwt", JwtVcSdJwt, {
    credential_definition: CredentialDefinition,
    vct: String,
    order: Option<String>
});

#[derive(Serialize, Deserialize, Debug, PartialEq,Eq,Clone)]
#[serde(untagged)]
pub enum StringOrVec {
    One(String),
    Many(Vec<String>)
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct CredentialDefinition {
    #[serde(rename = "type")]
    pub type_: StringOrVec,
    #[serde(flatten)]
    pub credential_subject: CredentialSubject,
}
