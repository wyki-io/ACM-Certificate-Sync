mod aws;

use super::common::TLS;

use async_trait::async_trait;
pub use aws::AcmAlbDestination;

#[async_trait]
pub trait Destination {
    fn name(&self) -> String;
    async fn publish(&self, tls: TLS) -> anyhow::Result<()>;
}
