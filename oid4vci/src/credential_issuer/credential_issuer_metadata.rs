use super::credential_configurations_supported::CredentialConfigurationsSupportedObject;
use crate::credential_format_profiles::{CredentialFormatCollection, CredentialFormats, WithParameters};
use derivative::Derivative;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct CredentialResponseEncryption {
    pub alg_values_supported: Vec<String>,
    pub enc_values_supported: Vec<String>,
    pub encryption_required: bool,
}

/// Credential Issuer Metadata as described here:
/// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-13.html#name-credential-issuer-metadata-p
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Derivative)]
#[derivative(Default)]
pub struct CredentialIssuerMetadata<CFC = CredentialFormats<WithParameters>>
where
    CFC: CredentialFormatCollection,
{
    // TODO: Temporary solution
    #[derivative(Default(value = "Url::parse(\"https://example.com\").unwrap()"))]
    pub credential_issuer: Url,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub authorization_servers: Vec<Url>,
    // TODO: Temporary solution
    #[derivative(Default(value = "Url::parse(\"https://example.com\").unwrap()"))]
    pub credential_endpoint: Url,
    pub batch_credential_endpoint: Option<Url>,
    pub deferred_credential_endpoint: Option<Url>,
    pub notification_endpoint: Option<Url>,
    pub credential_response_encryption: Option<CredentialResponseEncryption>,
    pub credential_identifiers_supported: Option<bool>,
    pub signed_metadata: Option<String>,
    pub display: Option<Vec<serde_json::Value>>,
    pub credential_configurations_supported: HashMap<String, CredentialConfigurationsSupportedObject<CFC>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        credential_format_profiles::{
            w3c_verifiable_credentials::{jwt_vc_json::{self, StringOrVec}, CredentialSubject},
            CredentialFormats, Parameters, WithParameters,
        },
        proof::KeyProofMetadata,
        ProofType,
    };
    use serde::de::DeserializeOwned;
    use serde_json::json;
    use std::{fs::File, path::Path};

    fn json_example<T>(path: &str) -> T
    where
        T: DeserializeOwned,
    {
        let file_path = Path::new(path);
        let file = File::open(file_path).expect("file does not exist");
        serde_json::from_reader::<_, T>(file).expect("could not parse json")
    }

    #[test]
    fn test_oid4vci_examples() {
        // Examples from
        // https://github.com/openid/OpenID4VCI/tree/80b2214814106e55e5fd09af3415ba4fc124b6be/examples

        assert_eq!(
            CredentialIssuerMetadata {
                credential_issuer: "https://credential-issuer.example.com".parse().unwrap(),
                authorization_servers: vec!["https://server.example.com".parse().unwrap()],
                credential_endpoint: Url::parse("https://credential-issuer.example.com").unwrap(),
                batch_credential_endpoint: Some(
                    "https://credential-issuer.example.com/batch_credential"
                        .parse()
                        .unwrap()
                ),
                deferred_credential_endpoint: Some(
                    "https://credential-issuer.example.com/deferred_credential"
                        .parse()
                        .unwrap()
                ),
                notification_endpoint: None,
                credential_response_encryption: Some(CredentialResponseEncryption {
                    alg_values_supported: vec!["ECDH-ES".to_string()],
                    enc_values_supported: vec!["A128GCM".to_string()],
                    encryption_required: false
                }),
                credential_identifiers_supported: None,
                signed_metadata: None,
                display: Some(vec![
                    json!({
                        "name": "Example University",
                        "locale": "en-US"
                    }),
                    json!({
                        "name": "Example Université",
                        "locale": "fr-FR"
                    })
                ]),
                credential_configurations_supported: vec![(
                    "UniversityDegreeCredential".to_string(),
                    CredentialConfigurationsSupportedObject {
                        credential_format: CredentialFormats::<WithParameters>::JwtVcJson(Parameters {
                            parameters: (
                                jwt_vc_json::CredentialDefinition {
                                    type_: StringOrVec::Many(vec![
                                        "VerifiableCredential".to_string(),
                                        "UniversityDegreeCredential".to_string()
                                    ]),
                                    credential_subject: CredentialSubject {
                                        credential_subject: Some(json!({
                                            "given_name": {
                                                "display": [
                                                    {
                                                        "name": "Given Name",
                                                        "locale": "en-US"
                                                    },
                                                ]
                                            },
                                            "family_name": {
                                                "display": [
                                                    {
                                                        "name": "Surname",
                                                        "locale": "en-US"
                                                    }
                                                ]
                                            },
                                            "degree": {},
                                            "gpa": {
                                                "display": [
                                                    {
                                                        "name": "GPA"
                                                    }
                                                ]
                                            }
                                        }))
                                    }
                                },
                                None
                            )
                                .into()
                        }),
                        scope: Some("UniversityDegree".to_string()),
                        cryptographic_binding_methods_supported: vec!["did:example".to_string()],
                        credential_signing_alg_values_supported: vec!["ES256".to_string()],
                        proof_types_supported: vec![(
                            ProofType::Jwt,
                            KeyProofMetadata {
                                proof_signing_alg_values_supported: vec!["ES256".to_string()]
                            }
                        )]
                        .into_iter()
                        .collect(),
                        display: vec![json!({
                            "name": "University Credential",
                            "locale": "en-US",
                            "logo": {
                                "url": "https://university.example.edu/public/logo.png",
                                "alt_text": "a square logo of a university"
                            },
                            "background_color": "#12107c",
                            "text_color": "#FFFFFF"
                        })],
                    },
                ),]
                .into_iter()
                .collect(),
            },
            json_example::<CredentialIssuerMetadata>("tests/examples/credential_issuer_metadata_jwt_vc_json.json")
        );
    }
}
