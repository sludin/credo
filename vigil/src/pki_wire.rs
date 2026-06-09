/// DER-encoded OCSP response and CRL construction.
///
/// Builds RFC 6960 OCSPResponse and RFC 5280 CertificateList using the raw DER
/// helpers from ca.rs. Signature uses the intermediate CA key.
use anyhow::{bail, Context, Result};

use crate::ca::{
    decode_der_length_pub, der_context_constructed, der_generalized_time, der_integer_hex,
    der_octet_string, der_sequence, encode_oid, load_signing_key,
};
use crate::config::VigilConfig;
use crate::storage;
use crate::types::RootCAMetadata;

// ---------------------------------------------------------------------------
// Extra DER helpers (not already in ca.rs)
// ---------------------------------------------------------------------------

fn der_enumerated(v: u8) -> Vec<u8> {
    vec![0x0a, 0x01, v]
}

fn der_bit_string_raw(sig_der: &[u8]) -> Vec<u8> {
    // BIT STRING: tag 0x03 | length | 0x00 (unused bits) | signature
    let mut content = vec![0x00u8];
    content.extend_from_slice(sig_der);
    let mut out = vec![0x03u8];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xff) as u8);
    }
    out.extend_from_slice(&content);
    out
}

// ---------------------------------------------------------------------------
// OCSP error response (e.g. malformedRequest = 1)
// ---------------------------------------------------------------------------

pub fn build_ocsp_error_response(status_code: u8) -> Vec<u8> {
    der_sequence(&der_enumerated(status_code))
}

// ---------------------------------------------------------------------------
// OCSP request parsing
// ---------------------------------------------------------------------------

pub struct ParsedOcspRequest {
    pub cert_id_der: Vec<u8>,
    pub serial_number: String,
}

/// Parse a DER OCSPRequest; extract the first CertID and its serial number.
pub fn parse_ocsp_request(der_request: &[u8]) -> Result<ParsedOcspRequest> {
    let cert_id_der = find_first_cert_id(der_request)
        .ok_or_else(|| anyhow::anyhow!("OCSP request: CertID not found"))?;
    let serial_number = extract_serial_from_cert_id(&cert_id_der)?;
    Ok(ParsedOcspRequest {
        cert_id_der,
        serial_number,
    })
}

/// Walk the DER tree to find the first SEQUENCE that looks like a CertID.
fn find_first_cert_id(data: &[u8]) -> Option<Vec<u8>> {
    let mut pos = 0;
    while pos < data.len() {
        let tag = data[pos];
        let (len_size, len) = decode_der_length_pub(&data[pos + 1..])?;
        let content_start = pos + 1 + len_size;
        let content_end = content_start + len;
        if content_end > data.len() {
            break;
        }
        let content = &data[content_start..content_end];

        if tag == 0x30 {
            if looks_like_cert_id(content) {
                return Some(data[pos..content_end].to_vec());
            }
            if let Some(found) = find_first_cert_id(content) {
                return Some(found);
            }
        } else if tag & 0xe0 == 0xa0 {
            // Context-specific constructed
            if let Some(found) = find_first_cert_id(content) {
                return Some(found);
            }
        }
        pos = content_end;
    }
    None
}

/// Returns true if content looks like a CertID:
/// SEQUENCE { SEQUENCE(AlgId), OCTET STRING, OCTET STRING, INTEGER }
fn looks_like_cert_id(content: &[u8]) -> bool {
    let expected = [0x30u8, 0x04, 0x04, 0x02];
    let mut pos = 0;
    for &expected_tag in &expected {
        if pos >= content.len() || content[pos] != expected_tag {
            return false;
        }
        let (ls, l) = match decode_der_length_pub(&content[pos + 1..]) {
            Some(x) => x,
            None => return false,
        };
        pos += 1 + ls + l;
    }
    true
}

fn extract_serial_from_cert_id(cert_id_der: &[u8]) -> Result<String> {
    if cert_id_der.is_empty() || cert_id_der[0] != 0x30 {
        bail!("CertID: not a SEQUENCE");
    }
    let (outer_ls, _outer_len) = decode_der_length_pub(&cert_id_der[1..])
        .ok_or_else(|| anyhow::anyhow!("CertID outer length"))?;
    let mut pos = 1 + outer_ls;

    // Skip AlgorithmIdentifier (SEQUENCE)
    pos = skip_tlv(cert_id_der, pos)?;
    // Skip issuerNameHash (OCTET STRING)
    pos = skip_tlv(cert_id_der, pos)?;
    // Skip issuerKeyHash (OCTET STRING)
    pos = skip_tlv(cert_id_der, pos)?;

    // Read serialNumber (INTEGER tag 0x02)
    if pos >= cert_id_der.len() || cert_id_der[pos] != 0x02 {
        bail!("CertID: expected INTEGER for serialNumber");
    }
    let (ls, l) = decode_der_length_pub(&cert_id_der[pos + 1..])
        .ok_or_else(|| anyhow::anyhow!("CertID serial length"))?;
    let serial_bytes = &cert_id_der[pos + 1 + ls..pos + 1 + ls + l];
    let trimmed = if serial_bytes.first() == Some(&0x00) {
        &serial_bytes[1..]
    } else {
        serial_bytes
    };
    let hex = hex::encode(trimmed).trim_start_matches('0').to_string();
    Ok(if hex.is_empty() { "0".to_string() } else { hex })
}

fn skip_tlv(data: &[u8], pos: usize) -> Result<usize> {
    if pos >= data.len() {
        bail!("skip_tlv: out of bounds");
    }
    let (ls, l) = decode_der_length_pub(&data[pos + 1..])
        .ok_or_else(|| anyhow::anyhow!("skip_tlv: invalid length"))?;
    Ok(pos + 1 + ls + l)
}

// ---------------------------------------------------------------------------
// OCSP response
// ---------------------------------------------------------------------------

pub fn build_ocsp_response_from_request(
    der_request: &[u8],
    max_age_seconds: u32,
    config: &VigilConfig,
) -> Result<Vec<u8>> {
    let parsed = parse_ocsp_request(der_request).context("Parsing OCSP request")?;
    let record = storage::find_certificate_by_serial(&config.cert_db_path, &parsed.serial_number)?;

    let (status, revoked_at) = match &record {
        None => ("unknown", None),
        Some(r) if r.revoked => ("revoked", r.revoked_at.as_deref()),
        Some(_) => ("good", None),
    };

    build_ocsp_success_response(
        &parsed.cert_id_der,
        status,
        revoked_at,
        max_age_seconds,
        config,
    )
}

fn build_ocsp_success_response(
    cert_id_der: &[u8],
    status: &str,
    revoked_at: Option<&str>,
    max_age_seconds: u32,
    config: &VigilConfig,
) -> Result<Vec<u8>> {
    let key_pem = std::fs::read_to_string(&config.ca_ecdsa_intermediate_key_path)?;
    let cert_pem_raw = std::fs::read_to_string(&config.ca_ecdsa_intermediate_cert_path)?;
    let signing_key = load_signing_key(&key_pem)?;

    let now_iso = chrono::Utc::now().to_rfc3339();
    let next_iso =
        (chrono::Utc::now() + chrono::Duration::seconds(max_age_seconds as i64)).to_rfc3339();

    // certStatus
    let cert_status: Vec<u8> = match status {
        "good" => vec![0x80, 0x00],
        "revoked" => {
            let rt = revoked_at.unwrap_or(&now_iso);
            der_context_constructed(1, &der_sequence(&der_generalized_time(rt)))
        }
        _ => vec![0x82, 0x00],
    };

    let next_update_der = der_context_constructed(0, &der_generalized_time(&next_iso));
    let single_response = der_sequence(
        &[
            cert_id_der,
            &cert_status,
            &der_generalized_time(&now_iso),
            &next_update_der,
        ]
        .concat(),
    );

    // issuer subject for responderID
    let ca_der = pem::parse(cert_pem_raw.trim())?.into_contents();
    let issuer_subject = issuer_subject_from_cert_der(&ca_der)?;
    let responder_id = der_context_constructed(1, &issuer_subject);

    // ResponseData
    let resp_data_content: Vec<u8> = [
        responder_id.as_slice(),
        der_generalized_time(&now_iso).as_slice(),
        der_sequence(&single_response).as_slice(),
    ]
    .concat();
    let response_data = der_sequence(&resp_data_content);

    // Sign
    let sig_bytes = signing_key.sign(&response_data)?;
    let sig_bit = der_bit_string_raw(&sig_bytes);

    // Attach CA cert
    let certs_field = der_context_constructed(0, &der_sequence(&ca_der));

    let basic_content: Vec<u8> = [
        response_data.as_slice(),
        signing_key.sig_alg_identifier_der().as_slice(),
        sig_bit.as_slice(),
        certs_field.as_slice(),
    ]
    .concat();
    let basic_ocsp = der_sequence(&basic_content);

    // responseBytes
    let oid_bytes = encode_oid("1.3.6.1.5.5.7.48.1.1");
    let octet = der_octet_string(&basic_ocsp);
    let resp_bytes = der_sequence(&[oid_bytes.as_slice(), octet.as_slice()].concat());
    let resp_bytes_explicit = der_context_constructed(0, &resp_bytes);

    // OCSPResponse: successful(0) + responseBytes
    let enum_0 = der_enumerated(0);
    let ocsp_response = der_sequence(&[enum_0.as_slice(), resp_bytes_explicit.as_slice()].concat());
    Ok(ocsp_response)
}

fn issuer_subject_from_cert_der(cert_der: &[u8]) -> Result<Vec<u8>> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der)
        .map_err(|e| anyhow::anyhow!("Parsing CA cert: {:?}", e))?;
    Ok(cert.subject().as_raw().to_vec())
}

// ---------------------------------------------------------------------------
// CRL
// ---------------------------------------------------------------------------

pub fn build_signed_crl_der(
    _root_ca: &RootCAMetadata,
    next_update_hours: u32,
    config: &VigilConfig,
) -> Result<Vec<u8>> {
    let key_pem = std::fs::read_to_string(&config.ca_ecdsa_intermediate_key_path)?;
    let cert_pem_raw = std::fs::read_to_string(&config.ca_ecdsa_intermediate_cert_path)?;
    let signing_key = load_signing_key(&key_pem)?;

    let ca_der = pem::parse(cert_pem_raw.trim())?.into_contents();
    let issuer_subject = issuer_subject_from_cert_der(&ca_der)?;

    let now_iso = chrono::Utc::now().to_rfc3339();
    let next_iso =
        (chrono::Utc::now() + chrono::Duration::hours(next_update_hours as i64)).to_rfc3339();

    let records = storage::list_certificate_records(&config.cert_db_path)?;
    let revoked_entries: Vec<u8> = records
        .iter()
        .filter(|r| r.revoked)
        .flat_map(|r| {
            let ra = r.revoked_at.as_deref().unwrap_or(&now_iso);
            der_sequence(&[der_integer_hex(&r.serial_number), der_generalized_time(ra)].concat())
        })
        .collect();

    let sig_alg = signing_key.sig_alg_identifier_der();
    let mut tbs = Vec::new();
    tbs.extend_from_slice(&der_integer_hex("01")); // version 2 (value 1)
    tbs.extend_from_slice(&sig_alg);
    tbs.extend_from_slice(&issuer_subject);
    tbs.extend_from_slice(&der_generalized_time(&now_iso));
    tbs.extend_from_slice(&der_generalized_time(&next_iso));
    if !revoked_entries.is_empty() {
        tbs.extend_from_slice(&der_sequence(&revoked_entries));
    }
    let tbs_cert_list = der_sequence(&tbs);

    let sig_bytes = signing_key.sign(&tbs_cert_list)?;
    let sig_bit = der_bit_string_raw(&sig_bytes);

    Ok(der_sequence(
        &[
            tbs_cert_list.as_slice(),
            sig_alg.as_slice(),
            sig_bit.as_slice(),
        ]
        .concat(),
    ))
}

pub fn build_signed_crl_pem(
    root_ca: &RootCAMetadata,
    next_update_hours: u32,
    config: &VigilConfig,
) -> Result<String> {
    let der = build_signed_crl_der(root_ca, next_update_hours, config)?;
    let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &der)
        .chars()
        .collect::<Vec<char>>()
        .chunks(64)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("\n");
    Ok(format!(
        "-----BEGIN X509 CRL-----\n{}\n-----END X509 CRL-----\n",
        b64
    ))
}
