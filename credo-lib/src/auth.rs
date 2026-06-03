use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use crate::error::AppError;
use crate::types::{ClientIdentity, Role};

// ---------------------------------------------------------------------------
// Fingerprinting
// ---------------------------------------------------------------------------

pub fn fingerprint_der(der: &[u8]) -> String {
    hex::encode(Sha256::digest(der))
}

// ---------------------------------------------------------------------------
// Identity parsing
// ---------------------------------------------------------------------------

/// Parse raw DER cert bytes into a ClientIdentity.
pub fn identity_from_der(der: &[u8]) -> Result<ClientIdentity> {
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|e| anyhow::anyhow!("Parsing client cert: {:?}", e))?;

    let subject = cert.subject().to_string();
    let fingerprint256 = fingerprint_der(der);
    let mut san_uris = Vec::new();
    let mut san_dns = Vec::new();

    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for name in &san.general_names {
                match name {
                    GeneralName::DNSName(dns) => san_dns.push(dns.to_string()),
                    GeneralName::URI(uri)     => san_uris.push(uri.to_string()),
                    _ => {}
                }
            }
        }
    }

    Ok(ClientIdentity { fingerprint256, subject, san_uris, san_dns })
}

/// Parse the leaf cert from a PEM chain into a ClientIdentity.
pub fn identity_from_pem(pem_str: &str) -> Result<ClientIdentity> {
    let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(pem_str.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
        .context("Parsing client cert PEM")?;
    let leaf = certs
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("No certificate found in PEM"))?;
    identity_from_der(leaf.as_ref())
}

/// Parse a cert from a proxy-forwarded header value.
/// Accepts PEM (nginx/haproxy) and base64 DER (Caddy).
pub fn identity_from_header(raw: &str) -> Option<ClientIdentity> {
    let decoded = percent_decode(raw).replace('\t', "\n");
    let trimmed = decoded.trim();

    if trimmed.contains("-----BEGIN CERTIFICATE-----") {
        return identity_from_pem(trimmed).ok();
    }

    use base64::{engine::general_purpose::STANDARD, Engine};
    let clean: String = trimmed.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    STANDARD.decode(&clean).ok().and_then(|der| identity_from_der(&der).ok())
}

fn percent_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '%' {
            let h1 = chars.next().unwrap_or('0');
            let h2 = chars.next().unwrap_or('0');
            if let Ok(byte) = u8::from_str_radix(&format!("{}{}", h1, h2), 16) {
                out.push(byte as char);
            } else {
                out.push('%'); out.push(h1); out.push(h2);
            }
        } else {
            out.push(c);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Role enforcement
// ---------------------------------------------------------------------------

/// Verify the resolved role meets the minimum required level.
/// Returns `Unauthorized` if no role (unauthenticated), `Forbidden` if too low.
pub fn check_min_role(role: Option<&Role>, min: &Role) -> Result<(), AppError> {
    let r = role.ok_or_else(|| AppError::Unauthorized("No authenticated identity".to_string()))?;
    if r.rank() < min.rank() {
        return Err(AppError::Forbidden("Insufficient permissions.".to_string()));
    }
    Ok(())
}
