use anyhow::Result;
use async_trait::async_trait;
use std::sync::Arc;

#[async_trait]
pub trait Sign: Send + Sync {
    // TODO: add this?
    async fn jwt_header(&self) -> jsonwebtoken::Header;
    async fn key_id(&self, subject_syntax_type: &str) -> Option<String>;
    async fn sign(&self, message: &str, subject_syntax_type: &str) -> Result<Vec<u8>>;
    fn external_signer(&self) -> Option<Arc<dyn ExternalSign>>;
}

pub trait ExternalSign: Send + Sync {
    fn sign(&self, message: &str) -> Result<Vec<u8>>;
}
