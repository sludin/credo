#![allow(dead_code)]

use anyhow::Result;

pub mod he;

pub struct DnsProviderContext {
    pub record_name: String,
    pub txt_value: String,
    pub identifier: String,
}

pub trait DnsProvider: Send + Sync {
    fn create<'a>(
        &'a self,
        ctx: &'a DnsProviderContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>;
    fn cleanup<'a>(
        &'a self,
        ctx: &'a DnsProviderContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>;
}

pub fn create_provider(name: &str, _config: &serde_json::Value) -> Result<Box<dyn DnsProvider>> {
    match name {
        "he" => Ok(Box::new(he::HeProvider::new(_config)?)),
        other => anyhow::bail!("Unknown DNS provider: {other}"),
    }
}
