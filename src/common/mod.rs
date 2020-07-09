#[derive(Debug, Default)]
pub struct TLS {
    pub domain: String,
    pub key: String,
    pub cert: String,
    pub chain: Option<String>,
}

impl TLS {
    pub fn new(domain: String, key: String, cert: String, chain: Option<String>) -> Self {
        TLS {
            domain,
            key,
            cert,
            chain,
        }
    }
}
