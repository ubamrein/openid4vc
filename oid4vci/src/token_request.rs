use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

/// Token Request as described here: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-13.html#name-token-request
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(tag = "grant_type")]
pub enum TokenRequest {
    #[serde(rename = "authorization_code")]
    AuthorizationCode {
        code: String,
        code_verifier: Option<String>,
        redirect_uri: Option<String>,
        client_id: Option<String>
    },
    #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    PreAuthorizedCode {
        #[serde(rename = "pre-authorized_code")]
        pre_authorized_code: String,
        tx_code: Option<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_request_serde() {
        assert_eq!(
            serde_urlencoded::from_str::<TokenRequest>(
                "grant_type=authorization_code\
        &code=SplxlOBeZQQYbYS6WxSbIA\
        &code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk\
        &redirect_uri=https%3A%2F%2FWallet.example.org%2Fcb",
            )
            .unwrap(),
            TokenRequest::AuthorizationCode {
                code: "SplxlOBeZQQYbYS6WxSbIA".to_string(),
                code_verifier: Some("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_string()),
                redirect_uri: Some("https://Wallet.example.org/cb".to_string()),
                client_id: None
            }
        );

        assert_eq!(
            serde_urlencoded::from_str::<TokenRequest>(
                "grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code\
                &pre-authorized_code=SplxlOBeZQQYbYS6WxSbIA\
                &tx_code=493536"
            )
            .unwrap(),
            TokenRequest::PreAuthorizedCode {
                pre_authorized_code: "SplxlOBeZQQYbYS6WxSbIA".to_string(),
                tx_code: Some("493536".to_string())
            }
        );
    }
}
