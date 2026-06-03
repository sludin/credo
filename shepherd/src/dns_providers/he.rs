use anyhow::{bail, Context, Result};
use std::future::Future;
use std::pin::Pin;

use super::{DnsProvider, DnsProviderContext};

pub struct HeProvider {
    ddns_key: String,
}

impl HeProvider {
    pub fn new(config: &serde_json::Value) -> Result<Self> {
        let key = config
            .get("ddnsKey")
            .and_then(|v| v.as_str())
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "DNS provider 'he' requires a non-empty 'ddnsKey' in providerConfig"
                )
            })?;
        Ok(Self { ddns_key: key.trim().to_string() })
    }

    async fn update(ddns_key: String, record_name: String, txt_value: String) -> Result<()> {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .context("Building HE DNS HTTP client")?;

        let resp = client
            .post("https://dyn.dns.he.net/nic/update")
            .form(&[
                ("hostname", record_name.as_str()),
                ("password", ddns_key.as_str()),
                ("txt", txt_value.as_str()),
            ])
            .send()
            .await
            .context("POST to dyn.dns.he.net")?;

        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();

        if !status.is_success() {
            bail!("dns.he.net update failed with HTTP {status}: {text}");
        }

        let normalized = text.trim().to_lowercase();
        if !normalized.starts_with("good") && !normalized.starts_with("nochg") {
            bail!("dns.he.net update rejected for {record_name}: {text}");
        }

        Ok(())
    }
}

impl DnsProvider for HeProvider {
    fn create<'a>(
        &'a self,
        ctx: &'a DnsProviderContext,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        let key = self.ddns_key.clone();
        let name = ctx.record_name.clone();
        let value = ctx.txt_value.clone();
        Box::pin(async move { Self::update(key, name, value).await })
    }

    fn cleanup<'a>(
        &'a self,
        ctx: &'a DnsProviderContext,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        let key = self.ddns_key.clone();
        let name = ctx.record_name.clone();
        Box::pin(async move { Self::update(key, name, "empty".to_string()).await })
    }
}
