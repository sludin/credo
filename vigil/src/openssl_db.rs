/// Manages the OpenSSL flat-file CA database: serial, index.txt, newcerts/.
///
/// serial    - next serial number in hex; read, used, incremented on each issuance.
/// index.txt - tab-delimited log of all certs.
/// newcerts/ - copy of every issued cert stored as <SERIAL>.pem.
///
/// All functions are optional — if the serial file is absent, callers use random serials.
use anyhow::Result;
use std::path::{Path, PathBuf};

fn normalize_serial(serial: &str) -> String {
    let s = serial.trim().to_uppercase().replace(' ', "");
    if s.len().is_multiple_of(2) {
        s
    } else {
        format!("0{}", s)
    }
}

fn to_openssl_date(iso: &str) -> String {
    let dt = chrono::DateTime::parse_from_rfc3339(iso)
        .or_else(|_| chrono::DateTime::parse_from_rfc2822(iso))
        .unwrap_or_else(|_| chrono::Utc::now().fixed_offset());
    dt.format("%y%m%d%H%M%SZ").to_string()
}

fn to_openssl_subject(node_subject: &str) -> String {
    let parts: Vec<&str> = node_subject
        .split('\n')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    format!("/{}", parts.join("/"))
}

pub fn serial_path(ca_dir: &Path) -> PathBuf {
    ca_dir.join("serial")
}

pub fn has_openssl_db(ca_dir: &Path) -> bool {
    serial_path(ca_dir).exists()
}

/// Read current serial, return it, then write next serial.
pub fn read_and_increment_serial(ca_dir: &Path) -> Result<String> {
    let path = serial_path(ca_dir);
    let current = normalize_serial(&std::fs::read_to_string(&path)?);
    let current_int = u64::from_str_radix(&current, 16)?;
    let next = normalize_serial(&format!("{:X}", current_int + 1));
    std::fs::write(&path, format!("{}\n", next))?;
    Ok(current)
}

pub fn write_new_cert(ca_dir: &Path, serial_hex: &str, cert_pem: &str) -> Result<()> {
    let new_certs_dir = ca_dir.join("newcerts");
    std::fs::create_dir_all(&new_certs_dir)?;
    std::fs::write(
        new_certs_dir.join(format!("{}.pem", normalize_serial(serial_hex))),
        cert_pem,
    )?;
    Ok(())
}

pub fn append_valid_entry(
    ca_dir: &Path,
    serial_hex: &str,
    expiry_date: &str,
    subject: &str,
) -> Result<()> {
    let index_file = ca_dir.join("index.txt");
    let line = format!(
        "V\t{}\t\t{}\tunknown\t{}\n",
        to_openssl_date(expiry_date),
        normalize_serial(serial_hex),
        to_openssl_subject(subject),
    );
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(index_file)?;
    f.write_all(line.as_bytes())?;
    Ok(())
}

pub fn mark_revoked_in_index(ca_dir: &Path, serial_hex: &str, revoked_at: &str) -> Result<bool> {
    let index_file = ca_dir.join("index.txt");
    if !index_file.exists() {
        return Ok(false);
    }
    let serial = normalize_serial(serial_hex);
    let content = std::fs::read_to_string(&index_file)?;
    let mut found = false;
    let updated: Vec<String> = content
        .lines()
        .map(|line| {
            let fields: Vec<&str> = line.split('\t').collect();
            if fields.len() >= 4 && fields[0] == "V" && fields[3] == serial {
                found = true;
                let mut f = fields.to_vec();
                f[0] = "R";
                let rev_date = to_openssl_date(revoked_at);
                if f.len() > 2 {
                    f[2] = Box::leak(rev_date.into_boxed_str());
                }
                f.join("\t")
            } else {
                line.to_string()
            }
        })
        .collect();
    if found {
        std::fs::write(&index_file, updated.join("\n"))?;
    }
    Ok(found)
}

pub fn find_ca_dir_for_serial(serial_hex: &str, ca_dirs: &[PathBuf]) -> Option<PathBuf> {
    let serial = normalize_serial(serial_hex);
    for ca_dir in ca_dirs {
        let index_file = ca_dir.join("index.txt");
        if !index_file.exists() {
            continue;
        }
        if let Ok(content) = std::fs::read_to_string(&index_file) {
            if content.lines().any(|line| {
                let fields: Vec<&str> = line.split('\t').collect();
                fields.len() >= 4 && fields[3] == serial
            }) {
                return Some(ca_dir.clone());
            }
        }
    }
    None
}
