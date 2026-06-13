use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::types::{
    AcmeCaConfig, AcmeTlsConfig, CaConfig, ExternalAccountBinding, ValidationMethodConfig,
};

// ---------------------------------------------------------------------------
// Raw JSON shapes for shepherd.ca.json
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct CaFile {
    cas: HashMap<String, RawCaEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawCaEntry {
    protocol: String,
    #[serde(default)]
    provider: String,
    config: Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawAcmeConfig {
    directory_url: String,
    account_email: Option<String>,
    account_key_path: String,
    renew_before_days: Option<f64>,
    days: Option<u32>,
    // EAB
    external_account_binding: Option<RawEab>,
    // Validation defaults keyed by method name
    validation: Option<HashMap<String, RawValidationConfig>>,
    supported_validations: Option<Vec<String>>,
    default_validation: Option<String>,
    // mTLS to ACME CA — nested form
    tls: Option<RawTlsBlock>,
    // mTLS to ACME CA — flat form (tlsCert / tlsKey / ca / caPath)
    tls_cert: Option<String>,
    tls_key: Option<String>,
    ca: Option<String>,
    ca_path: Option<String>,
    insecure_skip_verify: Option<bool>,
    rate_limits: Option<RawRateLimits>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawTlsBlock {
    cert_path: Option<String>,
    key_path: Option<String>,
    ca_path: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawEab {
    kid: String,
    hmac_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawValidationConfig {
    provider: Option<String>,
    provider_config: Option<Value>,
    propagation_delay_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawRateLimit {
    count: u32,
    window_days: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawRateLimits {
    certificates_per_domain: Option<RawRateLimit>,
    duplicate_certificates: Option<RawRateLimit>,
}

// ---------------------------------------------------------------------------
// Loader
// ---------------------------------------------------------------------------

pub fn load_cas(path: &Path) -> Result<HashMap<String, CaConfig>> {
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let base = path.parent().unwrap_or(Path::new("."));
    let value = credo_lib::config::load_json_config(path)
        .with_context(|| format!("Loading CA config: {}", path.display()))?;
    let file: CaFile = serde_json::from_value(value)
        .with_context(|| format!("Parsing CA config: {}", path.display()))?;

    let mut out = HashMap::new();
    for (name, entry) in file.cas {
        let ca =
            parse_ca_entry(&name, entry, base).with_context(|| format!("Parsing CA '{name}'"))?;
        out.insert(name, ca);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_ca_json(dir: &TempDir, body: &str) -> std::path::PathBuf {
        let path = dir.path().join("shepherd.ca.json");
        std::fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn load_cas_with_rate_limits() {
        let dir = TempDir::new().unwrap();
        let path = write_ca_json(
            &dir,
            r#"{
            "cas": {
                "letsencrypt": {
                    "protocol": "acme",
                    "provider": "letsencrypt",
                    "config": {
                        "directoryUrl": "https://acme-v02.api.letsencrypt.org/directory",
                        "accountKeyPath": "/tmp/account.pem",
                        "rateLimits": {
                            "certificatesPerDomain": {"count": 50, "windowDays": 7},
                            "duplicateCertificates": {"count": 5, "windowDays": 7}
                        }
                    }
                }
            }
        }"#,
        );

        let cas = load_cas(&path).unwrap();
        let le = cas.get("letsencrypt").unwrap();
        let rl = le.config.rate_limits.as_ref().unwrap();
        let cpd = rl.certificates_per_domain.as_ref().unwrap();
        assert_eq!(cpd.count, 50);
        assert_eq!(cpd.window_days, 7);
        let dc = rl.duplicate_certificates.as_ref().unwrap();
        assert_eq!(dc.count, 5);
        assert_eq!(dc.window_days, 7);
    }

    #[test]
    fn load_cas_without_rate_limits_is_none() {
        let dir = TempDir::new().unwrap();
        let path = write_ca_json(
            &dir,
            r#"{
            "cas": {
                "vigil": {
                    "protocol": "acme",
                    "provider": "vigil",
                    "config": {
                        "directoryUrl": "https://vigil.example.com:7020/acme/directory",
                        "accountKeyPath": "/tmp/account.pem"
                    }
                }
            }
        }"#,
        );

        let cas = load_cas(&path).unwrap();
        let vigil = cas.get("vigil").unwrap();
        assert!(vigil.config.rate_limits.is_none());
    }

    #[test]
    fn load_cas_partial_rate_limits() {
        let dir = TempDir::new().unwrap();
        let path = write_ca_json(
            &dir,
            r#"{
            "cas": {
                "myca": {
                    "protocol": "acme",
                    "provider": "myca",
                    "config": {
                        "directoryUrl": "https://acme.example.com/directory",
                        "accountKeyPath": "/tmp/account.pem",
                        "rateLimits": {
                            "certificatesPerDomain": {"count": 100, "windowDays": 30}
                        }
                    }
                }
            }
        }"#,
        );

        let cas = load_cas(&path).unwrap();
        let ca = cas.get("myca").unwrap();
        let rl = ca.config.rate_limits.as_ref().unwrap();
        let cpd = rl.certificates_per_domain.as_ref().unwrap();
        assert_eq!(cpd.count, 100);
        assert_eq!(cpd.window_days, 30);
        assert!(rl.duplicate_certificates.is_none());
    }
}

fn parse_ca_entry(name: &str, entry: RawCaEntry, base: &Path) -> Result<CaConfig> {
    if entry.protocol != "acme" {
        anyhow::bail!(
            "CA '{}' uses unsupported protocol '{}'",
            name,
            entry.protocol
        );
    }

    let raw: RawAcmeConfig = serde_json::from_value(entry.config)
        .with_context(|| format!("Parsing ACME config for CA '{name}'"))?;

    let resolve = |s: &str| -> PathBuf {
        let p = Path::new(s);
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            base.join(p)
        }
    };

    // TLS: nested block takes priority over flat fields
    let tls = {
        let cert_path = raw
            .tls
            .as_ref()
            .and_then(|t| t.cert_path.as_deref())
            .or(raw.tls_cert.as_deref())
            .map(resolve);
        let key_path = raw
            .tls
            .as_ref()
            .and_then(|t| t.key_path.as_deref())
            .or(raw.tls_key.as_deref())
            .map(resolve);
        let ca_path = raw
            .tls
            .as_ref()
            .and_then(|t| t.ca_path.as_deref())
            .or(raw.ca_path.as_deref())
            .or(raw.ca.as_deref())
            .map(resolve);
        if cert_path.is_some() || key_path.is_some() || ca_path.is_some() {
            Some(AcmeTlsConfig {
                cert_path,
                key_path,
                ca_path,
            })
        } else {
            None
        }
    };

    let validation: HashMap<String, ValidationMethodConfig> = raw
        .validation
        .unwrap_or_default()
        .into_iter()
        .map(|(k, v)| {
            (
                k,
                ValidationMethodConfig {
                    provider: v.provider,
                    provider_config: v.provider_config,
                    propagation_delay_seconds: v.propagation_delay_seconds,
                },
            )
        })
        .collect();

    let supported_validations = raw
        .supported_validations
        .unwrap_or_else(|| vec!["none-01".into(), "dns-01".into(), "http-01".into()]);

    let default_validation = raw
        .default_validation
        .or_else(|| supported_validations.first().cloned())
        .unwrap_or_else(|| "dns-01".into());

    Ok(CaConfig {
        name: name.to_string(),
        protocol: "acme".to_string(),
        provider: entry.provider,
        config: AcmeCaConfig {
            directory_url: raw.directory_url,
            account_email: raw.account_email,
            account_key_path: resolve(&raw.account_key_path),
            renew_before_days: raw.renew_before_days,
            days: raw.days,
            eab: raw
                .external_account_binding
                .map(|e| ExternalAccountBinding {
                    kid: e.kid,
                    hmac_key: e.hmac_key,
                }),
            validation,
            supported_validations,
            default_validation,
            tls,
            insecure_skip_verify: raw.insecure_skip_verify.unwrap_or(false),
            rate_limits: raw.rate_limits.map(|rl| crate::types::CaRateLimits {
                certificates_per_domain: rl.certificates_per_domain.map(|l| {
                    crate::types::CaRateLimit {
                        count: l.count,
                        window_days: l.window_days,
                    }
                }),
                duplicate_certificates: rl.duplicate_certificates.map(|l| {
                    crate::types::CaRateLimit {
                        count: l.count,
                        window_days: l.window_days,
                    }
                }),
            }),
        },
    })
}
