mod aws;

use super::common::TLS;

use async_trait::async_trait;
pub use aws::AcmAlbProvider;

#[async_trait]
pub trait Provider {
    fn name(&self) -> String;
    async fn publish(&self, tls: TLS) -> anyhow::Result<()>;
}
