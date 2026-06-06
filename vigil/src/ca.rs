/// Certificate Authority operations: CSR signing, cert chain assembly.
///
/// Vigil always signs with the ECDSA intermediate key (root stays offline).
/// CSR signing is done via raw DER construction to support any key type.
use anyhow::{bail, Context, Result};
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::path::Path;

use crate::config::VigilConfig;
use crate::types::{RootCAMetadata, SignedCertificate};

// ---------------------------------------------------------------------------
// DER encoding helpers (minimal implementation for TBSCertificate construction)
// ---------------------------------------------------------------------------

fn der_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else if len < 0x10000 {
        vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
    } else {
        vec![
            0x83,
            (len >> 16) as u8,
            ((len >> 8) & 0xFF) as u8,
            (len & 0xFF) as u8,
        ]
    }
}

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&der_length(content.len()));
    out.extend_from_slice(content);
    out
}

pub fn der_sequence(content: &[u8]) -> Vec<u8> { der_tlv(0x30, content) }
pub fn der_context_constructed(tag: u8, content: &[u8]) -> Vec<u8> { der_tlv(0xa0 | tag, content) }
pub fn der_context_primitive(tag: u8, content: &[u8]) -> Vec<u8> { der_tlv(0x80 | tag, content) }
pub fn der_octet_string(content: &[u8]) -> Vec<u8> { der_tlv(0x04, content) }

/// Integer from raw bytes (MSB preserved; zero-extends if high bit set).
pub fn der_integer_bytes(bytes: &[u8]) -> Vec<u8> {
    // Strip leading zeros but keep at least one byte; if MSB >= 0x80 prepend 0x00
    let stripped: &[u8] = bytes.iter().position(|&b| b != 0)
        .map(|i| &bytes[i..])
        .unwrap_or(&bytes[..1]);
    let content: Vec<u8> = if !stripped.is_empty() && stripped[0] >= 0x80 {
        let mut v = vec![0x00];
        v.extend_from_slice(stripped);
        v
    } else {
        stripped.to_vec()
    };
    der_tlv(0x02, &content)
}

/// Integer from a hex string (positive).
pub fn der_integer_hex(hex: &str) -> Vec<u8> {
    let normalized = hex.trim().trim_start_matches("0x");
    let padded = if normalized.len() % 2 != 0 {
        format!("0{}", normalized)
    } else {
        normalized.to_string()
    };
    let bytes = hex::decode(&padded).unwrap_or_else(|_| vec![0]);
    der_integer_bytes(&bytes)
}

fn der_bit_string_der_sig(sig_der: &[u8]) -> Vec<u8> {
    // BIT STRING: 0x03 | len | 0x00 (unused bits) | content
    let mut content = vec![0x00u8];
    content.extend_from_slice(sig_der);
    der_tlv(0x03, &content)
}

fn der_utctime(dt: &chrono::DateTime<Utc>) -> Vec<u8> {
    // YYMMDDHHMMSSZ
    let s = dt.format("%y%m%d%H%M%SZ").to_string();
    der_tlv(0x17, s.as_bytes())
}

fn encode_oid_component(n: u64) -> Vec<u8> {
    if n < 128 {
        return vec![n as u8];
    }
    let mut parts = Vec::new();
    let mut val = n;
    parts.push((val & 0x7F) as u8);
    val >>= 7;
    while val > 0 {
        parts.push(0x80 | (val & 0x7F) as u8);
        val >>= 7;
    }
    parts.reverse();
    parts
}

pub fn encode_oid(oid: &str) -> Vec<u8> {
    let components: Vec<u64> = oid.split('.').map(|s| s.parse::<u64>().unwrap_or(0)).collect();
    if components.len() < 2 {
        return der_tlv(0x06, &[]);
    }
    let mut content = vec![(components[0] * 40 + components[1]) as u8];
    for &c in &components[2..] {
        content.extend_from_slice(&encode_oid_component(c));
    }
    der_tlv(0x06, &content)
}

fn der_null() -> Vec<u8> { vec![0x05, 0x00] }

fn der_boolean_true() -> Vec<u8> { der_tlv(0x01, &[0xff]) }

// ---------------------------------------------------------------------------
// Extension building
// ---------------------------------------------------------------------------

fn build_basic_constraints_ext() -> Vec<u8> {
    // BasicConstraints: SEQUENCE {} (cA = FALSE, implicit)
    let bc_value = der_sequence(&[]);
    let ext_value = der_octet_string(&bc_value);
    // Extension: SEQUENCE { OID, BOOLEAN TRUE, OCTET STRING }
    let oid = encode_oid("2.5.29.19");
    let critical = der_boolean_true();
    der_sequence(&[oid, critical, ext_value].concat())
}

fn build_key_usage_ext() -> Vec<u8> {
    // KeyUsage: BIT STRING with digitalSignature (bit 0 = 0x80, unused = 7, but actually bit 0)
    // ASN.1 BIT STRING: 0x03 len unused_bits bitflags
    // digitalSignature is bit 0 (MSB of first octet), unused bits = 7
    let ku_bitstring = vec![0x03, 0x02, 0x07, 0x80u8];
    let ext_value = der_octet_string(&ku_bitstring);
    let oid = encode_oid("2.5.29.15");
    let critical = der_boolean_true();
    der_sequence(&[oid, critical, ext_value].concat())
}

fn is_ip_san(name: &str) -> bool {
    let parts: Vec<&str> = name.split('.').collect();
    if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
        return true;
    }
    false
}

fn is_uri_san(name: &str) -> bool {
    name.contains("://")
}

fn build_san_extension(names: &[String]) -> Vec<u8> {
    if names.is_empty() {
        return vec![];
    }
    let general_names: Vec<u8> = names.iter().flat_map(|name| {
        let n = name.trim();
        if is_ip_san(n) {
            // iPAddress [7] IMPLICIT
            let parts: Vec<u8> = n.split('.').map(|p| p.parse::<u8>().unwrap_or(0)).collect();
            der_context_primitive(7, &parts)
        } else if is_uri_san(n) {
            // uniformResourceIdentifier [6] IMPLICIT IA5String
            der_context_primitive(6, n.as_bytes())
        } else {
            // dNSName [2] IMPLICIT IA5String
            der_context_primitive(2, n.as_bytes())
        }
    }).collect();

    let san_sequence = der_sequence(&general_names);
    let ext_value = der_octet_string(&san_sequence);
    let oid = encode_oid("2.5.29.17");
    der_sequence(&[oid, ext_value].concat())
}

// ---------------------------------------------------------------------------
// Signing key abstraction (ECDSA P-256 / P-384, RSA)
// ---------------------------------------------------------------------------

pub enum CaSigningKey {
    EcdsaP256(Box<p256::ecdsa::SigningKey>),
    EcdsaP384(Box<p384::ecdsa::SigningKey>),
    Rsa(Box<rsa::pkcs1v15::SigningKey<sha2::Sha256>>),
}

impl CaSigningKey {
    pub fn sig_alg_oid(&self) -> &'static str {
        match self {
            CaSigningKey::EcdsaP256(_) => "1.2.840.10045.4.3.2",  // ecdsa-with-SHA256
            CaSigningKey::EcdsaP384(_) => "1.2.840.10045.4.3.3",  // ecdsa-with-SHA384
            CaSigningKey::Rsa(_)       => "1.2.840.113549.1.1.11", // sha256WithRSAEncryption
        }
    }

    pub fn sig_alg_identifier_der(&self) -> Vec<u8> {
        let oid = encode_oid(self.sig_alg_oid());
        match self {
            // ECDSA: no NULL parameter
            CaSigningKey::EcdsaP256(_) | CaSigningKey::EcdsaP384(_) => der_sequence(&oid),
            // RSA: AlgorithmIdentifier { OID, NULL }
            CaSigningKey::Rsa(_) => der_sequence(&[oid, der_null()].concat()),
        }
    }

    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            CaSigningKey::EcdsaP256(key) => {
                use p256::ecdsa::signature::Signer;
                let sig: p256::ecdsa::DerSignature = key.sign(data);
                Ok(sig.as_bytes().to_vec())
            }
            CaSigningKey::EcdsaP384(key) => {
                use p384::ecdsa::signature::Signer;
                let sig: p384::ecdsa::DerSignature = key.sign(data);
                Ok(sig.as_bytes().to_vec())
            }
            CaSigningKey::Rsa(key) => {
                use rsa::signature::SignatureEncoding;
                use rsa::signature::Signer;
                let sig: rsa::pkcs1v15::Signature = key.sign(data);
                Ok(sig.to_bytes().to_vec())
            }
        }
    }
}

pub fn load_signing_key(pem: &str) -> Result<CaSigningKey> {
    use pkcs8::DecodePrivateKey;

    // Try ECDSA P-384 first (default curve)
    if let Ok(key) = p384::SecretKey::from_pkcs8_pem(pem) {
        return Ok(CaSigningKey::EcdsaP384(Box::new(p384::ecdsa::SigningKey::from(&key))));
    }
    // Try ECDSA P-256
    if let Ok(key) = p256::SecretKey::from_pkcs8_pem(pem) {
        return Ok(CaSigningKey::EcdsaP256(Box::new(p256::ecdsa::SigningKey::from(&key))));
    }
    // Try RSA
    if let Ok(priv_key) = rsa::RsaPrivateKey::from_pkcs8_pem(pem) {
        let signing_key = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(priv_key);
        return Ok(CaSigningKey::Rsa(Box::new(signing_key)));
    }
    // Also try SEC1 PEM (EC PRIVATE KEY header)
    if let Ok(key) = p384::SecretKey::from_sec1_pem(pem) {
        return Ok(CaSigningKey::EcdsaP384(Box::new(p384::ecdsa::SigningKey::from(&key))));
    }
    if let Ok(key) = p256::SecretKey::from_sec1_pem(pem) {
        return Ok(CaSigningKey::EcdsaP256(Box::new(p256::ecdsa::SigningKey::from(&key))));
    }
    bail!("Failed to load CA signing key from PEM — supported types: ECDSA P-256/P-384, RSA")
}

// ---------------------------------------------------------------------------
// CA loading
// ---------------------------------------------------------------------------

pub fn load_ca_metadata(config: &VigilConfig) -> Result<RootCAMetadata> {
    let cert_path = &config.ca_ecdsa_intermediate_cert_path;
    let key_path = &config.ca_ecdsa_intermediate_key_path;

    if !cert_path.exists() {
        bail!(
            "ECDSA intermediate cert not found: {}\n\
             Run the ceremony scripts to generate CA material.",
            cert_path.display()
        );
    }
    if !key_path.exists() {
        bail!(
            "ECDSA intermediate key not found: {}\n\
             Run the ceremony scripts to generate CA material.",
            key_path.display()
        );
    }

    let cert_pem = std::fs::read_to_string(cert_path)
        .with_context(|| format!("Reading CA cert: {}", cert_path.display()))?;

    parse_cert_metadata(&cert_pem, key_path, cert_path)
}

fn parse_cert_metadata(cert_pem: &str, key_path: &Path, cert_path: &Path) -> Result<RootCAMetadata> {
    let der = pem::parse(cert_pem.trim())
        .with_context(|| "Parsing CA cert PEM")?
        .into_contents();

    let (_, cert) = x509_parser::parse_x509_certificate(&der)
        .map_err(|e| anyhow::anyhow!("Parsing CA cert DER: {:?}", e))?;

    let subject = cert.subject().to_string();
    let serial_number = cert.serial.to_str_radix(16).to_uppercase();
    let valid_from = cert.validity().not_before.to_rfc2822()
        .unwrap_or_else(|_| cert.validity().not_before.to_string());
    let valid_to = cert.validity().not_after.to_rfc2822()
        .unwrap_or_else(|_| cert.validity().not_after.to_string());
    let fingerprint256 = format!("SHA256:{}", hex::encode(Sha256::digest(&der)));

    Ok(RootCAMetadata {
        subject,
        serial_number,
        valid_from,
        valid_to,
        fingerprint256,
        key_path: key_path.to_string_lossy().into_owned(),
        cert_path: cert_path.to_string_lossy().into_owned(),
    })
}

// ---------------------------------------------------------------------------
// CSR extraction helpers
// ---------------------------------------------------------------------------

struct CsrFields {
    /// Raw DER bytes of the Subject RDNSequence
    subject_der: Vec<u8>,
    /// Raw DER bytes of the SubjectPublicKeyInfo
    spki_der: Vec<u8>,
    /// SAN names from the CSR (DNS names, URIs, IPs as strings)
    san_names: Vec<String>,
    /// CN value if present
    cn: Option<String>,
}

fn extract_csr_fields(csr_der: &[u8]) -> Result<CsrFields> {
    use x509_parser::prelude::FromDer;
    let (_, csr) = x509_parser::certification_request::X509CertificationRequest::from_der(csr_der)
        .map_err(|e| anyhow::anyhow!("Parsing CSR: {:?}", e))?;

    let cri = &csr.certification_request_info;

    // Subject raw DER
    let subject_der = cri.subject.as_raw().to_vec();

    // CN
    let cn = cri.subject.iter_attributes()
        .find_map(|attr| attr.attr_value().as_str().ok().map(|s| s.to_string()));

    // SPKI — re-encode from raw bytes. x509-parser stores the raw DER slice
    // We need the full SPKI TLV. Navigate the CertificationRequestInfo DER to find it.
    let spki_der = extract_spki_der(csr_der)?;

    // SANs from requested extensions
    let mut san_names = Vec::new();
    for ext_result in csr.requested_extensions().into_iter().flatten() {
        if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) = ext_result {
            for name in &san.general_names {
                match name {
                    x509_parser::extensions::GeneralName::DNSName(dns) => {
                        san_names.push(dns.trim().to_string());
                    }
                    x509_parser::extensions::GeneralName::URI(uri) => {
                        san_names.push(uri.trim().to_string());
                    }
                    x509_parser::extensions::GeneralName::IPAddress(ip) => {
                        if ip.len() == 4 {
                            san_names.push(format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]));
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(CsrFields { subject_der, spki_der, san_names, cn })
}

/// Extract the SubjectPublicKeyInfo DER bytes from a CSR DER blob.
/// CSR structure: SEQUENCE { SEQUENCE { INTEGER version, SEQUENCE subject, SEQUENCE spki, [0] attrs }, ... }
fn extract_spki_der(csr_der: &[u8]) -> Result<Vec<u8>> {
    // Navigate: CertificationRequest → CertificationRequestInfo → SPKI
    let (cri_content, _) = der_read_sequence(csr_der)
        .ok_or_else(|| anyhow::anyhow!("CSR: outer SEQUENCE parse failed"))?;
    let (cri_inner, _) = der_read_sequence(cri_content)
        .ok_or_else(|| anyhow::anyhow!("CSR: CertificationRequestInfo SEQUENCE parse failed"))?;
    // CertificationRequestInfo: INTEGER(version), SEQUENCE(subject), SEQUENCE(spki), [0](attrs)
    let after_version = der_skip_tlv(cri_inner)
        .ok_or_else(|| anyhow::anyhow!("CSR: skip version failed"))?;
    let after_subject = der_skip_tlv(after_version)
        .ok_or_else(|| anyhow::anyhow!("CSR: skip subject failed"))?;
    // Now at SPKI
    let (spki_bytes, _) = der_read_tlv(after_subject)
        .ok_or_else(|| anyhow::anyhow!("CSR: SPKI parse failed"))?;
    Ok(spki_bytes.to_vec())
}

/// Read a DER TLV: returns (full TLV bytes, remainder)
fn der_read_tlv(data: &[u8]) -> Option<(&[u8], &[u8])> {
    if data.is_empty() { return None; }
    let tag_len = 1usize;
    let (len_size, len) = decode_der_length(&data[tag_len..])?;
    let header_size = tag_len + len_size;
    let total = header_size + len;
    if data.len() < total { return None; }
    Some((&data[..total], &data[total..]))
}

/// Skip one DER TLV and return the remainder.
fn der_skip_tlv(data: &[u8]) -> Option<&[u8]> {
    der_read_tlv(data).map(|(_, rest)| rest)
}

/// Read a SEQUENCE: returns (inner content, remainder)
fn der_read_sequence(data: &[u8]) -> Option<(&[u8], &[u8])> {
    if data.is_empty() || data[0] != 0x30 { return None; }
    let (len_size, len) = decode_der_length(&data[1..])?;
    let header_size = 1 + len_size;
    let total = header_size + len;
    if data.len() < total { return None; }
    Some((&data[header_size..total], &data[total..]))
}

fn decode_der_length(data: &[u8]) -> Option<(usize, usize)> {
    decode_der_length_pub(data)
}

/// Public DER length decoder used by pki_wire.rs.
pub fn decode_der_length_pub(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() { return None; }
    if data[0] < 0x80 {
        Some((1, data[0] as usize))
    } else {
        let num_bytes = (data[0] & 0x7F) as usize;
        if data.len() < 1 + num_bytes { return None; }
        let mut len = 0usize;
        for &b in &data[1..1 + num_bytes] {
            len = (len << 8) | (b as usize);
        }
        Some((1 + num_bytes, len))
    }
}

/// Public DER TLV reader used by pki_wire.rs.
pub fn der_read_tlv_pub(data: &[u8]) -> Option<(&[u8], &[u8])> {
    der_read_tlv(data)
}

/// Build a DER GeneralizedTime (YYYYMMDDHHMMSSZ) from an ISO 8601 string.
pub fn der_generalized_time(iso: &str) -> Vec<u8> {
    let dt = chrono::DateTime::parse_from_rfc3339(iso)
        .map(|d| d.with_timezone(&chrono::Utc))
        .unwrap_or_else(|_| chrono::Utc::now());
    let s = dt.format("%Y%m%d%H%M%SZ").to_string();
    let mut out = vec![0x18u8];
    out.push(s.len() as u8);
    out.extend_from_slice(s.as_bytes());
    out
}

// ---------------------------------------------------------------------------
// CSR signing — main entry point
// ---------------------------------------------------------------------------

pub fn sign_csr(
    csr_pem: &str,
    days: u32,
    extra_sans: Option<&[String]>,
    config: &VigilConfig,
) -> Result<SignedCertificate> {
    let csr_der = pem::parse(csr_pem.trim())
        .context("Parsing CSR PEM")?
        .into_contents();

    let fields = extract_csr_fields(&csr_der).context("Extracting CSR fields")?;

    let key_pem = std::fs::read_to_string(&config.ca_ecdsa_intermediate_key_path)
        .context("Reading CA signing key")?;
    let cert_pem = std::fs::read_to_string(&config.ca_ecdsa_intermediate_cert_path)
        .context("Reading CA signing cert")?;

    let signing_key = load_signing_key(&key_pem).context("Loading CA signing key")?;

    // CA cert DER — get issuer subject
    let ca_der = pem::parse(cert_pem.trim())
        .context("Parsing CA cert PEM")?
        .into_contents();
    let issuer_der = extract_subject_der(&ca_der)?;

    // Serial: read from OpenSSL DB if available, else random
    let ca_dir = config.ca_ecdsa_intermediate_cert_path
        .parent()
        .and_then(|p| p.parent())
        .unwrap_or(config.ca_dir.as_path());

    let (serial_hex, used_openssl_db) = if crate::openssl_db::has_openssl_db(ca_dir) {
        let s = crate::openssl_db::read_and_increment_serial(ca_dir)?;
        (s, true)
    } else {
        let random_bytes: Vec<u8> = (0..16).map(|_| rand::random::<u8>()).collect();
        (hex::encode(random_bytes), false)
    };

    // Build SAN list: CSR SANs + CN + extra
    let mut san_set: Vec<String> = fields.san_names.clone();
    if let Some(cn) = &fields.cn {
        let cn = cn.trim().to_string();
        if !cn.is_empty() && !san_set.contains(&cn) {
            san_set.push(cn);
        }
    }
    if let Some(extras) = extra_sans {
        for s in extras {
            let s = s.trim().to_string();
            if !s.is_empty() && !san_set.contains(&s) {
                san_set.push(s);
            }
        }
    }

    let now = Utc::now();
    let valid_to = now + chrono::Duration::days(days as i64);

    // Build extensions
    let bc_ext = build_basic_constraints_ext();
    let ku_ext = build_key_usage_ext();
    let san_ext = build_san_extension(&san_set);
    let mut ext_list: Vec<u8> = Vec::new();
    ext_list.extend_from_slice(&bc_ext);
    ext_list.extend_from_slice(&ku_ext);
    if !san_ext.is_empty() {
        ext_list.extend_from_slice(&san_ext);
    }
    let extensions_seq = der_sequence(&ext_list);
    let extensions_outer = der_context_constructed(3, &extensions_seq);

    // Version v3: [0] INTEGER 2
    let version = der_context_constructed(0, &der_integer_bytes(&[0x02]));

    let serial_der = der_integer_hex(&serial_hex);
    let sig_alg = signing_key.sig_alg_identifier_der();
    let validity = der_sequence(&[der_utctime(&now), der_utctime(&valid_to)].concat());

    // TBSCertificate
    let tbs_content: Vec<u8> = [
        version.as_slice(),
        &serial_der,
        &sig_alg,
        &issuer_der,
        &validity,
        &fields.subject_der,
        &fields.spki_der,
        &extensions_outer,
    ]
    .concat();
    let tbs = der_sequence(&tbs_content);

    // Sign the TBSCertificate
    let sig_bytes = signing_key.sign(&tbs).context("Signing TBS certificate")?;
    let sig_bit_string = der_bit_string_der_sig(&sig_bytes);

    // Build full Certificate
    let cert_content = [tbs.as_slice(), &sig_alg, &sig_bit_string].concat();
    let cert_der = der_sequence(&cert_content);

    // PEM-encode
    let cert_pem_str = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &cert_der)
            .chars()
            .collect::<Vec<char>>()
            .chunks(64)
            .map(|c| c.iter().collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    );

    // Update OpenSSL DB if we used it
    let cert_meta = parse_cert_der_metadata(&cert_der)?;
    if used_openssl_db {
        let _ = crate::openssl_db::write_new_cert(ca_dir, &serial_hex, &cert_pem_str);
        let _ = crate::openssl_db::append_valid_entry(ca_dir, &serial_hex, &cert_meta.valid_to, &cert_meta.subject);
    }

    let chain_pem = format!("{}\n", cert_pem.trim());
    let fullchain_pem = format!("{}{}", cert_pem_str, chain_pem);

    Ok(SignedCertificate {
        id: cert_meta.serial_number.to_lowercase(),
        serial_number: cert_meta.serial_number,
        subject: cert_meta.subject,
        valid_from: cert_meta.valid_from,
        valid_to: cert_meta.valid_to,
        fingerprint256: cert_meta.fingerprint256,
        cert_pem: cert_pem_str,
        chain_pem,
        fullchain_pem,
    })
}

/// Extract the subject DER bytes from a CA cert — used as the issuer field in certs signed by that CA.
/// TBSCertificate: [0]version, INTEGER serial, AlgId, SEQUENCE issuer, SEQUENCE validity, SEQUENCE subject
fn extract_subject_der(cert_der: &[u8]) -> Result<Vec<u8>> {
    let (cert_content, _) = der_read_sequence(cert_der)
        .ok_or_else(|| anyhow::anyhow!("Cert: outer SEQUENCE parse failed"))?;
    let (tbs_content, _) = der_read_sequence(cert_content)
        .ok_or_else(|| anyhow::anyhow!("Cert: TBS SEQUENCE parse failed"))?;
    let after_version = der_skip_tlv(tbs_content)
        .ok_or_else(|| anyhow::anyhow!("Cert: skip version failed"))?;
    let after_serial = der_skip_tlv(after_version)
        .ok_or_else(|| anyhow::anyhow!("Cert: skip serial failed"))?;
    let after_alg = der_skip_tlv(after_serial)
        .ok_or_else(|| anyhow::anyhow!("Cert: skip algorithm failed"))?;
    let after_issuer = der_skip_tlv(after_alg)
        .ok_or_else(|| anyhow::anyhow!("Cert: skip issuer failed"))?;
    let after_validity = der_skip_tlv(after_issuer)
        .ok_or_else(|| anyhow::anyhow!("Cert: skip validity failed"))?;
    // Now at subject (SEQUENCE)
    let (subject_bytes, _) = der_read_tlv(after_validity)
        .ok_or_else(|| anyhow::anyhow!("Cert: subject TLV parse failed"))?;
    Ok(subject_bytes.to_vec())
}

// ---------------------------------------------------------------------------
// Cert metadata extraction from DER
// ---------------------------------------------------------------------------

struct CertMeta {
    serial_number: String,
    subject: String,
    valid_from: String,
    valid_to: String,
    fingerprint256: String,
}

fn parse_cert_der_metadata(cert_der: &[u8]) -> Result<CertMeta> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der)
        .map_err(|e| anyhow::anyhow!("Parsing issued cert: {:?}", e))?;

    let serial_number = cert.serial.to_str_radix(16).to_uppercase();
    let subject = cert.subject().to_string();
    let valid_from = cert.validity().not_before.to_rfc2822()
        .unwrap_or_else(|_| cert.validity().not_before.to_string());
    let valid_to = cert.validity().not_after.to_rfc2822()
        .unwrap_or_else(|_| cert.validity().not_after.to_string());
    let fingerprint256 = format!("SHA256:{}", hex::encode(Sha256::digest(cert_der)));

    Ok(CertMeta { serial_number, subject, valid_from, valid_to, fingerprint256 })
}

// ---------------------------------------------------------------------------
// Bootstrap ephemeral cert (1-day self-signed, uses rcgen)
// ---------------------------------------------------------------------------

pub fn generate_bootstrap_server_cert(
    common_name: &str,
    config: &VigilConfig,
) -> Result<(String, String, String)> {
    use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, SanType};

    let mut params = CertificateParams::new(vec![common_name.to_string()]);
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    params.distinguished_name = dn;
    params.subject_alt_names = vec![SanType::DnsName(common_name.to_string())];
    params.not_before = time::OffsetDateTime::now_utc();
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(1);

    let cert = Certificate::from_params(params)
        .context("Generating bootstrap cert params")?;

    let key_pem = cert.serialize_private_key_pem();
    let _cert_pem = cert.serialize_pem().context("Serializing bootstrap cert PEM")?;

    // Sign with our intermediate CA
    let ca_key_pem = std::fs::read_to_string(&config.ca_ecdsa_intermediate_key_path)?;
    let ca_cert_pem = std::fs::read_to_string(&config.ca_ecdsa_intermediate_cert_path)?;

    // Use the self-signed cert's CSR to get a CA-signed cert
    let csr_pem = cert.serialize_request_pem().context("Serializing bootstrap CSR")?;
    let signed = sign_csr(&csr_pem, 1, None, config).context("Signing bootstrap cert")?;
    let _ = (ca_key_pem, ca_cert_pem); // loaded inside sign_csr

    Ok((key_pem, signed.fullchain_pem, signed.chain_pem))
}
