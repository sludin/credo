use crate::storage;
use crate::types::{CrlEntry, CrlIssuer, CrlResponse, OcspStatusResponse, RootCAMetadata};
use anyhow::Result;
use std::path::Path;

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn next_update_from_seconds(seconds: u32) -> String {
    (chrono::Utc::now() + chrono::Duration::seconds(seconds as i64)).to_rfc3339()
}

fn next_update_from_hours(hours: u32) -> String {
    (chrono::Utc::now() + chrono::Duration::hours(hours as i64)).to_rfc3339()
}

pub fn get_ocsp_status_by_cert_id(
    db_path: &Path,
    cert_id: &str,
    max_age_seconds: u32,
) -> Result<OcspStatusResponse> {
    let record = storage::get_certificate_record(db_path, cert_id)?;
    Ok(map_ocsp(record.as_ref(), max_age_seconds))
}

pub fn get_ocsp_status_by_serial(
    db_path: &Path,
    serial: &str,
    max_age_seconds: u32,
) -> Result<OcspStatusResponse> {
    let record = storage::find_certificate_by_serial(db_path, serial)?;
    Ok(map_ocsp(record.as_ref(), max_age_seconds))
}

fn map_ocsp(
    record: Option<&crate::types::CertificateRecord>,
    max_age_seconds: u32,
) -> OcspStatusResponse {
    let produced_at = now_iso();
    let this_update = produced_at.clone();
    let next_update = next_update_from_seconds(max_age_seconds);

    let Some(record) = record else {
        return OcspStatusResponse {
            status: "unknown".to_string(),
            certificate_id: None,
            serial_number: None,
            this_update,
            next_update,
            produced_at,
            revoked_at: None,
            revoke_reason: None,
        };
    };

    if record.revoked {
        return OcspStatusResponse {
            status: "revoked".to_string(),
            certificate_id: Some(record.id.clone()),
            serial_number: Some(record.serial_number.clone()),
            this_update,
            next_update,
            produced_at,
            revoked_at: record.revoked_at.clone(),
            revoke_reason: record.revoke_reason.clone(),
        };
    }

    OcspStatusResponse {
        status: "good".to_string(),
        certificate_id: Some(record.id.clone()),
        serial_number: Some(record.serial_number.clone()),
        this_update,
        next_update,
        produced_at,
        revoked_at: None,
        revoke_reason: None,
    }
}

pub fn generate_crl(
    db_path: &Path,
    root_ca: &RootCAMetadata,
    next_update_hours: u32,
) -> Result<CrlResponse> {
    let generated_at = now_iso();
    let mut revoked_certificates: Vec<CrlEntry> = storage::list_certificate_records(db_path)?
        .into_iter()
        .filter(|r| r.revoked)
        .map(|r| CrlEntry {
            certificate_id: r.id.clone(),
            serial_number: r.serial_number.clone(),
            subject: r.subject.clone(),
            revoked_at: r.revoked_at.clone().unwrap_or_else(|| generated_at.clone()),
            revoke_reason: r
                .revoke_reason
                .clone()
                .unwrap_or_else(|| "unspecified".to_string()),
        })
        .collect();

    revoked_certificates.sort_by(|a, b| a.revoked_at.cmp(&b.revoked_at));

    Ok(CrlResponse {
        issuer: CrlIssuer {
            subject: root_ca.subject.clone(),
            serial_number: root_ca.serial_number.clone(),
            fingerprint256: root_ca.fingerprint256.clone(),
        },
        generated_at: generated_at.clone(),
        this_update: generated_at,
        next_update: next_update_from_hours(next_update_hours),
        revoked_certificates,
    })
}
