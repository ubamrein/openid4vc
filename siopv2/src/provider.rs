use std::str::FromStr;

use anyhow::Result;
use oid4vc_core::{
    authentication::subject::SigningSubject,
    authorization_request::{AuthorizationRequest, Body, ByReference, ByValue, Object},
    authorization_response::AuthorizationResponse,
    openid4vc_extension::{Extension, ResponseHandle},
    SubjectSyntaxType, Validator,
};
use reqwest::StatusCode;
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use reqwest_retry::{policies::ExponentialBackoff, RetryTransientMiddleware};

/// A Self-Issued OpenID Provider (SIOP), which is responsible for generating and signing [`IdToken`]'s in response to
/// [`AuthorizationRequest`]'s from [crate::relying_party::RelyingParty]'s (RPs). The [`Provider`] acts as a trusted intermediary between the RPs and
/// the user who is trying to authenticate.
pub struct Provider {
    pub subject: SigningSubject,
    pub default_subject_syntax_type: SubjectSyntaxType,
    client: ClientWithMiddleware,
}

impl Provider {
    // TODO: Use ProviderBuilder instead.
    pub fn new(subject: SigningSubject, default_subject_syntax_type: impl TryInto<SubjectSyntaxType>) -> Result<Self> {
        let retry_policy = ExponentialBackoff::builder().build_with_max_retries(5);
        let client = ClientBuilder::new(reqwest::Client::new())
            .with(RetryTransientMiddleware::new_with_policy(retry_policy))
            .build();
        Ok(Provider {
            subject,
            client,
            default_subject_syntax_type: default_subject_syntax_type
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid did method."))?,
        })
    }

    /// TODO: Add more validation rules.
    /// Takes a String and tries to parse it into an [`AuthorizationRequest<Object>`]. If the parsing fails, it tries to
    /// parse the [`AuthorizationRequest<Object>`] from the `request` parameter of the [`AuthorizationRequest<ByValue>`]
    /// or from the `request_uri` parameter of the [`AuthorizationRequest<ByReference>`].
    pub async fn validate_request(&self, authorization_request: String) -> Result<AuthorizationRequest<Object>> {
        let validator = Validator::Subject(self.subject.clone());

        let authorization_request = if let Ok(authorization_request) =
            authorization_request.parse::<AuthorizationRequest<Object>>()
        {
            authorization_request
        } else {
            let (client_id, authorization_request) =
                if let Ok(authorization_request) = AuthorizationRequest::<ByValue>::from_str(&authorization_request) {
                    let client_id = authorization_request.body.client_id().clone();
                    let authorization_request: AuthorizationRequest<Object> = validator
                        .decode(authorization_request.body.request.to_owned())
                        .await
                        .unwrap();

                    (client_id, authorization_request)
                } else if let Ok(authorization_request) =
                    AuthorizationRequest::<ByReference>::from_str(&authorization_request)
                {
                    let client_id = authorization_request.body.client_id().clone();
                    let builder = self.client.get(authorization_request.body.request_uri.clone());
                    let request_value = builder.send().await?.text().await?;
                    let authorization_request: AuthorizationRequest<Object> = validator.decode(request_value).await?;

                    (client_id, authorization_request)
                } else {
                    return Err(anyhow::anyhow!("Invalid authorization request."));
                };
            anyhow::ensure!(
                authorization_request.body.client_id == *client_id,
                "Client id mismatch."
            );
            authorization_request
        };

        Ok(authorization_request)
    }

    /// Generates an [`AuthorizationResponse`] in response to an [`AuthorizationRequest`] and the user's claims. The [`AuthorizationResponse`]
    /// contains an [`IdToken`], which is signed by the [`Subject`] of the [`Provider`].
    pub async fn generate_response<E: Extension>(
        &self,
        authorization_request: &AuthorizationRequest<Object<E>>,
        input: <E::ResponseHandle as ResponseHandle>::Input,
    ) -> Result<AuthorizationResponse<E>> {
        let redirect_uri = authorization_request.body.redirect_uri.to_string();
        let state = authorization_request.body.state.clone();

        let jwts = E::generate_token(
            self.subject.clone(),
            &authorization_request.body.client_id,
            &authorization_request.body.extension,
            &input,
            self.default_subject_syntax_type.clone(),
        )
        .await?;

        E::build_authorization_response(jwts, input, redirect_uri, state)
    }

    pub async fn send_response<E: Extension>(
        &self,
        authorization_response: &AuthorizationResponse<E>,
    ) -> Result<StatusCode> {
        Ok(self
            .client
            .post(authorization_response.redirect_uri.clone())
            .form(&authorization_response)
            .send()
            .await?
            .status())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{siopv2::SIOPv2, test_utils::TestSubject};
    use std::sync::Arc;

    #[tokio::test]
    async fn test_provider() {
        // Create a new subject and validator.
        let subject = TestSubject::new("did:test:123".to_string(), "key_id".to_string()).unwrap();

        // Create a new provider.
        let provider = Provider::new(Arc::new(subject), "did:test").unwrap();

        // Get a new SIOP authorization_request with response mode `direct_post` for cross-device communication.
        let request_url = "\
            siopv2://idtoken?\
                scope=openid\
                &response_type=id_token\
                &client_id=did%3Aexample%3AEiDrihTRe0GMdc3K16kgJB3Xbl9Hb8oqVHjzm6ufHcYDGA\
                &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb\
                &response_mode=direct_post\
                &client_metadata=%7B%22subject_syntax_types_supported%22%3A\
                %5B%22did%3Atest%22%5D%2C%0A%20%20%20%20\
                %22id_token_signing_alg_values_supported%22%3A%5B%22EdDSA%22%5D%7D\
                &nonce=n-0S6_WzA2Mj\
            ";

        // Let the provider validate the authorization_request.
        let authorization_request: AuthorizationRequest<Object> =
            provider.validate_request(request_url.to_string()).await.unwrap();

        let authorization_request =
            AuthorizationRequest::<Object<SIOPv2>>::from_generic(&authorization_request).unwrap();

        // Test whether the provider can generate a authorization_response for the authorization_request succesfully.
        assert!(provider
            .generate_response(&authorization_request, Default::default())
            .await
            .is_ok());
    }
}
