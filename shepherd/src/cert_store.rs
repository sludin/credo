use anyhow::{Context, Result};
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::path::Path;

use crate::types::CertStoreEntry;

// ---------------------------------------------------------------------------
// Full cert material (PEM strings + parsed metadata)
// ---------------------------------------------------------------------------

pub struct CertMaterial {
    pub cert_pem: String,
    pub chain_pem: Option<String>,
    pub fullchain_pem: Option<String>,
    pub key_pem: Option<String>,
    pub fingerprint256: String,
    pub expires_in_days: i64,
    pub ca: Option<String>,
}

pub fn read_cert_material(store_dir: &Path, cert_name: &str) -> Option<CertMaterial> {
    let live_dir = store_dir.join("live").join(cert_name);
    let cert_pem = std::fs::read_to_string(live_dir.join("cert.pem")).ok()?;
    let chain_pem = std::fs::read_to_string(live_dir.join("chain.pem")).ok();
    let fullchain_pem = std::fs::read_to_string(live_dir.join("fullchain.pem")).ok();
    let key_pem = std::fs::read_to_string(live_dir.join("privkey.pem")).ok();

    let der = pem_der(&cert_pem)?;
    let fingerprint256 = hex::encode(Sha256::digest(&der)).to_uppercase();
    let (_, cert) = x509_parser::parse_x509_certificate(&der).ok()?;
    let ts = cert.validity().not_after.timestamp();
    let expires_in_days = (ts - Utc::now().timestamp()) / 86400;

    Some(CertMaterial {
        cert_pem,
        chain_pem,
        fullchain_pem,
        key_pem,
        fingerprint256,
        expires_in_days,
        ca: None,
    })
}

// ---------------------------------------------------------------------------
// Layout:  <certStoreDir>/live/<certName>/cert.pem  (symlink → archive)
//          <certStoreDir>/archive/<certName>/cert-0001.pem  (actual file)
// ---------------------------------------------------------------------------

pub fn read_cert_store_entry(store_dir: &Path, cert_name: &str) -> Option<CertStoreEntry> {
    let cert_path = store_dir.join("live").join(cert_name).join("cert.pem");
    let pem_str = std::fs::read_to_string(&cert_path).ok()?;

    let der = pem_der(&pem_str)?;
    let (_, cert) = x509_parser::parse_x509_certificate(&der).ok()?;

    let fingerprint256 = hex::encode(Sha256::digest(&der)).to_uppercase();

    let not_after = cert.validity().not_after.timestamp();
    let valid_to = chrono::DateTime::from_timestamp(not_after, 0)?;
    let expires_in_days = (valid_to - Utc::now()).num_days();

    Some(CertStoreEntry {
        name: cert_name.to_string(),
        fingerprint256: Some(fingerprint256),
        valid_to: Some(valid_to),
        expires_in_days: Some(expires_in_days),
        subject: Some(cert.subject().to_string()),
    })
}

pub fn list_cert_store_entries(store_dir: &Path) -> Vec<String> {
    let live_dir = store_dir.join("live");
    std::fs::read_dir(&live_dir)
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .filter_map(|e| e.file_name().into_string().ok())
        .collect()
}

pub fn persist_issued_material(
    store_dir: &Path,
    cert_name: &str,
    cert_pem: &str,
    chain_pem: &str,
    fullchain_pem: &str,
    key_pem: Option<&str>,
) -> Result<()> {
    let archive_dir = store_dir.join("archive").join(cert_name);
    let live_dir    = store_dir.join("live").join(cert_name);
    std::fs::create_dir_all(&archive_dir).context("Creating archive dir")?;
    std::fs::create_dir_all(&live_dir).context("Creating live dir")?;

    let ordinal = next_ordinal(&archive_dir);

    let write = |name: &str, content: &str| -> Result<std::path::PathBuf> {
        let p = archive_dir.join(name);
        std::fs::write(&p, content)
            .with_context(|| format!("Writing {}", p.display()))?;
        Ok(p)
    };

    let cert_arc     = write(&format!("cert-{ordinal:04}.pem"), cert_pem)?;
    let chain_arc    = write(&format!("chain-{ordinal:04}.pem"), chain_pem)?;
    let full_arc     = write(&format!("fullchain-{ordinal:04}.pem"), fullchain_pem)?;

    replace_symlink(&cert_arc,  &live_dir.join("cert.pem"))?;
    replace_symlink(&chain_arc, &live_dir.join("chain.pem"))?;
    replace_symlink(&full_arc,  &live_dir.join("fullchain.pem"))?;

    if let Some(key) = key_pem {
        let key_arc = write(&format!("privkey-{ordinal:04}.pem"), key)?;
        replace_symlink(&key_arc, &live_dir.join("privkey.pem"))?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn pem_der(pem: &str) -> Option<Vec<u8>> {
    use rustls_pemfile::Item;
    let mut reader = std::io::BufReader::new(pem.as_bytes());
    rustls_pemfile::read_one(&mut reader).ok()?.and_then(|item| match item {
        Item::X509Certificate(der) => Some(der.to_vec()),
        _ => None,
    })
}

fn next_ordinal(archive_dir: &Path) -> u32 {
    std::fs::read_dir(archive_dir)
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            // match cert-NNNN.pem
            let stem = name.strip_prefix("cert-")?.strip_suffix(".pem")?;
            stem.parse::<u32>().ok()
        })
        .max()
        .map(|n| n + 1)
        .unwrap_or(1)
}

fn replace_symlink(target: &Path, link: &Path) -> Result<()> {
    if link.exists() || link.is_symlink() {
        std::fs::remove_file(link)
            .with_context(|| format!("Removing existing symlink {}", link.display()))?;
    }
    std::os::unix::fs::symlink(target, link)
        .with_context(|| format!("Creating symlink {} → {}", link.display(), target.display()))
}
