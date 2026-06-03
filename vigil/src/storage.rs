use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::types::{AcmeAccountRecord, CertificateRecord, VigilUser};

// ---------------------------------------------------------------------------
// DB wrapper types (match TypeScript's { users: [...] } format)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Default)]
struct UsersDb {
    users: Vec<VigilUser>,
}

#[derive(Serialize, Deserialize, Default)]
struct AcmeAccountsDb {
    accounts: Vec<AcmeAccountRecord>,
}

#[derive(Serialize, Deserialize, Default)]
struct CertificatesDb {
    certificates: Vec<CertificateRecord>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn normalize_serial(s: &str) -> String {
    let n = s.trim().trim_start_matches('0').to_lowercase();
    if n.is_empty() { "0".to_string() } else { n }
}

fn ensure_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Creating directory: {}", parent.display()))?;
    }
    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de> + Default>(path: &Path) -> Result<T> {
    if !path.exists() {
        return Ok(T::default());
    }
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Reading {}", path.display()))?;
    serde_json::from_str(&content)
        .with_context(|| format!("Parsing {}", path.display()))
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    ensure_parent(path)?;
    let json = serde_json::to_string_pretty(value)? + "\n";
    std::fs::write(path, json)
        .with_context(|| format!("Writing {}", path.display()))
}

pub fn normalize_pem(pem: &str) -> String {
    format!("{}\n", pem.replace('\r', "").trim())
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

pub fn ensure_users_db(path: &Path) -> Result<()> {
    if !path.exists() {
        ensure_parent(path)?;
        write_json(path, &UsersDb::default())?;
    }
    Ok(())
}

fn read_users_db(path: &Path) -> Result<UsersDb> {
    // Support legacy bare-array format
    if !path.exists() {
        return Ok(UsersDb::default());
    }
    let content = std::fs::read_to_string(path)?;
    let raw: serde_json::Value = serde_json::from_str(&content)?;
    if raw.is_array() {
        let users: Vec<VigilUser> = serde_json::from_value(raw)?;
        return Ok(UsersDb { users });
    }
    Ok(serde_json::from_value(raw)?)
}

pub fn list_users(path: &Path) -> Result<Vec<VigilUser>> {
    Ok(read_users_db(path)?.users)
}

pub fn add_user(path: &Path, user: VigilUser) -> Result<VigilUser> {
    let mut db = read_users_db(path)?;
    if db.users.iter().any(|u| u.id == user.id) {
        anyhow::bail!("user with id '{}' already exists", user.id);
    }
    let created = VigilUser {
        public_key_pem: normalize_pem(&user.public_key_pem),
        public_key_fingerprint256: user.public_key_fingerprint256.trim().to_lowercase(),
        ..user
    };
    db.users.push(created.clone());
    write_json(path, &db)?;
    Ok(created)
}

pub fn find_active_user_by_fingerprint(path: &Path, fingerprint: &str) -> Result<Option<VigilUser>> {
    let db = read_users_db(path)?;
    Ok(db.users.into_iter().find(|u| u.active && u.public_key_fingerprint256 == fingerprint))
}

// ---------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------

pub fn ensure_certs_db(db_path: &Path, certs_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(certs_dir)?;
    if !db_path.exists() {
        ensure_parent(db_path)?;
        write_json(db_path, &CertificatesDb::default())?;
    }
    Ok(())
}

fn read_certs_db(path: &Path) -> Result<CertificatesDb> {
    if !path.exists() {
        return Ok(CertificatesDb::default());
    }
    let content = std::fs::read_to_string(path)?;
    let raw: serde_json::Value = serde_json::from_str(&content)?;
    if raw.is_array() {
        let certs: Vec<CertificateRecord> = serde_json::from_value(raw)?;
        return Ok(CertificatesDb { certificates: certs });
    }
    Ok(serde_json::from_value(raw)?)
}

pub fn issue_certificate_record(
    db_path: &Path,
    certs_dir: &Path,
    record: CertificateRecord,
    fullchain_pem: &str,
) -> Result<CertificateRecord> {
    let cert_path = certs_dir.join(format!("{}.cert.pem", record.id));
    std::fs::write(&cert_path, normalize_pem(fullchain_pem))?;

    let full_record = CertificateRecord {
        cert_path: cert_path.to_string_lossy().into_owned(),
        ..record
    };

    let mut db = read_certs_db(db_path)?;
    db.certificates.retain(|c| c.id != full_record.id);
    db.certificates.push(full_record.clone());
    write_json(db_path, &db)?;
    Ok(full_record)
}

pub fn get_certificate_record(db_path: &Path, cert_id: &str) -> Result<Option<CertificateRecord>> {
    let db = read_certs_db(db_path)?;
    Ok(db.certificates.into_iter().find(|c| c.id == cert_id))
}

pub fn list_certificate_records(db_path: &Path) -> Result<Vec<CertificateRecord>> {
    Ok(read_certs_db(db_path)?.certificates)
}

pub fn find_certificate_by_serial(db_path: &Path, serial: &str) -> Result<Option<CertificateRecord>> {
    let wanted = normalize_serial(serial);
    let db = read_certs_db(db_path)?;
    Ok(db.certificates.into_iter().find(|c| normalize_serial(&c.serial_number) == wanted))
}

pub fn read_certificate_pem(cert_path: &str) -> Option<String> {
    std::fs::read_to_string(cert_path).ok()
}

pub fn revoke_certificate(
    db_path: &Path,
    cert_id: &str,
    revoked_by: &str,
    revoke_reason: &str,
    revoked_by_vigil_user_id: Option<String>,
    revoked_by_acme_account_id: Option<String>,
    revoked_via: Option<String>,
) -> Result<Option<CertificateRecord>> {
    let mut db = read_certs_db(db_path)?;
    let pos = db.certificates.iter().position(|c| c.id == cert_id);
    let Some(idx) = pos else { return Ok(None); };

    if db.certificates[idx].revoked {
        return Ok(Some(db.certificates[idx].clone()));
    }

    let existing = db.certificates[idx].clone();
    let updated = CertificateRecord {
        revoked: true,
        revoked_at: Some(chrono::Utc::now().to_rfc3339()),
        revoked_by: Some(revoked_by.to_string()),
        revoked_by_vigil_user_id,
        revoked_by_acme_account_id,
        revoked_via,
        revoke_reason: Some(revoke_reason.to_string()),
        ..existing
    };
    db.certificates[idx] = updated.clone();
    write_json(db_path, &db)?;
    Ok(Some(updated))
}

pub fn certificate_stats(db_path: &Path) -> Result<(usize, usize, usize)> {
    let db = read_certs_db(db_path)?;
    let total = db.certificates.len();
    let revoked = db.certificates.iter().filter(|c| c.revoked).count();
    Ok((total, revoked, total - revoked))
}

// ---------------------------------------------------------------------------
// ACME accounts
// ---------------------------------------------------------------------------

pub fn ensure_acme_accounts_db(path: &Path) -> Result<()> {
    if !path.exists() {
        ensure_parent(path)?;
        write_json(path, &AcmeAccountsDb::default())?;
    }
    Ok(())
}

pub fn read_acme_accounts(path: &Path) -> Result<Vec<AcmeAccountRecord>> {
    if !path.exists() {
        return Ok(vec![]);
    }
    let content = std::fs::read_to_string(path)?;
    let raw: serde_json::Value = serde_json::from_str(&content)?;
    if raw.is_array() {
        return Ok(serde_json::from_value(raw)?);
    }
    let db: AcmeAccountsDb = serde_json::from_value(raw)?;
    Ok(db.accounts)
}

pub fn write_acme_accounts(path: &Path, accounts: &[AcmeAccountRecord]) -> Result<()> {
    let db = AcmeAccountsDb { accounts: accounts.to_vec() };
    write_json(path, &db)
}

// ---------------------------------------------------------------------------
// Public key fingerprinting
// ---------------------------------------------------------------------------

pub fn fingerprint_public_key_pem(pem: &str) -> String {
    use sha2::{Digest, Sha256};
    let normalized = normalize_pem(pem);
    let hash = Sha256::digest(normalized.as_bytes());
    hex::encode(hash)
}
