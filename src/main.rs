use acs::{run, Provider, Receiver};

struct DummyReceiver {}

impl Receiver for DummyReceiver {
    fn receive() -> acs::TLS {
        todo!()
    }
}

struct DummyProvider {}

impl Provider for DummyProvider {
    fn publish(&self, tls: acs::TLS) {
        let _ = tls;
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let receiver = DummyReceiver {};
    let provider = DummyProvider {};
    run(receiver, provider).await
}
