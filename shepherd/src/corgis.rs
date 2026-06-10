use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

use crate::types::{CorgiMtlsConfig, CorgiNodeConfig};

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct RawMtls {
    cert_path: Option<String>,
    key_path: Option<String>,
    ca_path: Option<String>,
    // Bootstrap cert fallback: used when cert_path doesn't exist yet
    bootstrap_cert_path: Option<String>,
    bootstrap_key_path: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawDefaults {
    #[serde(default)]
    mtls: RawMtls,
    insecure_skip_verify: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawCorgi {
    name: String,
    url: String,
    identity_uri: Option<String>,
    #[serde(default)]
    mtls: RawMtls,
    insecure_skip_verify: Option<bool>,
    http_challenge_port: Option<u16>,
}

#[derive(Debug, Deserialize)]
struct CorgisFile {
    #[serde(default)]
    defaults: Option<RawDefaults>,
    #[serde(default)]
    corgis: Vec<RawCorgi>,
}

pub fn load_corgis(path: &Path) -> Result<Vec<CorgiNodeConfig>> {
    if !path.exists() {
        return Ok(vec![]);
    }
    let base = path.parent().unwrap_or(Path::new("."));
    let value = credo_lib::config::load_json_config(path)
        .with_context(|| format!("Loading corgis config: {}", path.display()))?;
    let file: CorgisFile = serde_json::from_value(value)
        .with_context(|| format!("Parsing corgis config: {}", path.display()))?;

    let defaults = file.defaults.as_ref();

    let mut result = Vec::with_capacity(file.corgis.len());
    for raw in &file.corgis {
        let cert_str = raw
            .mtls
            .cert_path
            .as_deref()
            .or_else(|| defaults.and_then(|d| d.mtls.cert_path.as_deref()))
            .with_context(|| format!("Corgi '{}': missing mtls.certPath", raw.name))?;
        let key_str = raw
            .mtls
            .key_path
            .as_deref()
            .or_else(|| defaults.and_then(|d| d.mtls.key_path.as_deref()))
            .with_context(|| format!("Corgi '{}': missing mtls.keyPath", raw.name))?;
        let ca_str = raw
            .mtls
            .ca_path
            .as_deref()
            .or_else(|| defaults.and_then(|d| d.mtls.ca_path.as_deref()));
        let bs_cert_str = raw
            .mtls
            .bootstrap_cert_path
            .as_deref()
            .or_else(|| defaults.and_then(|d| d.mtls.bootstrap_cert_path.as_deref()));
        let bs_key_str = raw
            .mtls
            .bootstrap_key_path
            .as_deref()
            .or_else(|| defaults.and_then(|d| d.mtls.bootstrap_key_path.as_deref()));

        let resolve = |s: &str| -> PathBuf {
            let p = Path::new(s);
            if p.is_absolute() {
                p.to_path_buf()
            } else {
                base.join(p)
            }
        };

        result.push(CorgiNodeConfig {
            name: raw.name.clone(),
            url: raw.url.clone(),
            identity_uri: raw.identity_uri.clone(),
            mtls: CorgiMtlsConfig {
                cert_path: resolve(cert_str),
                key_path: resolve(key_str),
                ca_path: ca_str.map(resolve),
                bootstrap_cert_path: bs_cert_str.map(resolve),
                bootstrap_key_path: bs_key_str.map(resolve),
            },
            insecure_skip_verify: raw
                .insecure_skip_verify
                .or_else(|| defaults.and_then(|d| d.insecure_skip_verify))
                .unwrap_or(false),
            http_challenge_port: raw.http_challenge_port,
        });
    }

    Ok(result)
}
