/// Certificate store file layout utilities.
///
/// Implements the certbot-style archive/live directory structure:
///   <store>/archive/<name>/cert-NNN.pem, key-NNN.pem, fullchain-NNN.pem, chain-NNN.pem
///   <store>/live/<name>/   → symlinks to latest archive entries
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// PEM chain splitting
// ---------------------------------------------------------------------------

pub struct PemChain {
    pub leaf_pem: String,
    pub chain_pem: String,
    pub fullchain_pem: String,
}

/// Split a PEM-encoded cert chain into leaf, intermediates, and fullchain.
/// Returns an error if no CERTIFICATE blocks are present.
pub fn split_pem_chain(pem: &str) -> Result<PemChain> {
    let certs: Vec<&str> = pem
        .split("-----END CERTIFICATE-----")
        .filter(|s| s.contains("-----BEGIN CERTIFICATE-----"))
        .map(|s| s.trim_start())
        .collect();

    if certs.is_empty() {
        bail!("No CERTIFICATE blocks found in PEM chain");
    }

    let leaf_pem = format!("{}-----END CERTIFICATE-----\n", certs[0]);
    let chain_parts: Vec<String> = certs[1..]
        .iter()
        .map(|s| format!("{}-----END CERTIFICATE-----\n", s))
        .collect();
    let chain_pem = chain_parts.join("");
    let fullchain_pem = format!("{}{}", leaf_pem, chain_pem);

    Ok(PemChain {
        leaf_pem,
        chain_pem,
        fullchain_pem,
    })
}

// ---------------------------------------------------------------------------
// Archive versioning
// ---------------------------------------------------------------------------

/// Pad a number to a 3-digit zero-prefixed ordinal string: 0 → "000", 42 → "042".
pub fn ordinal_string(n: u32) -> String {
    format!("{:03}", n)
}

/// Scan `archive_dir` for `fullchain-NNN.pem` files and return the next ordinal.
pub fn next_archive_ordinal(archive_dir: &Path) -> Result<u32> {
    if !archive_dir.exists() {
        return Ok(1);
    }
    let mut max = 0u32;
    for entry in std::fs::read_dir(archive_dir)
        .with_context(|| format!("Reading archive dir: {}", archive_dir.display()))?
    {
        let name = entry?.file_name();
        let name = name.to_string_lossy();
        if let Some(rest) = name.strip_prefix("fullchain-") {
            if let Some(num_str) = rest.strip_suffix(".pem") {
                if let Ok(n) = num_str.parse::<u32>() {
                    max = max.max(n);
                }
            }
        }
    }
    Ok(max + 1)
}

// ---------------------------------------------------------------------------
// Atomic symlink replacement
// ---------------------------------------------------------------------------

/// Delete any existing file or symlink at `link_path` and create a new
/// symlink pointing to `target_path`.
pub fn replace_symlink(target_path: &Path, link_path: &Path) -> Result<()> {
    if link_path.exists() || link_path.symlink_metadata().is_ok() {
        std::fs::remove_file(link_path)
            .with_context(|| format!("Removing old symlink: {}", link_path.display()))?;
    }
    std::os::unix::fs::symlink(target_path, link_path).with_context(|| {
        format!(
            "Creating symlink {} → {}",
            link_path.display(),
            target_path.display()
        )
    })
}

// ---------------------------------------------------------------------------
// CertStorePaths helper
// ---------------------------------------------------------------------------

pub struct CertStorePaths {
    pub archive_dir: PathBuf,
    pub live_dir: PathBuf,
}

impl CertStorePaths {
    pub fn new(store_root: &Path, cert_name: &str) -> Self {
        let safe = sanitize_cert_name(cert_name);
        CertStorePaths {
            archive_dir: store_root.join("archive").join(&safe),
            live_dir: store_root.join("live").join(&safe),
        }
    }

    pub fn ensure_dirs(&self) -> Result<()> {
        std::fs::create_dir_all(&self.archive_dir)?;
        std::fs::create_dir_all(&self.live_dir)?;
        Ok(())
    }
}

/// Replace characters that are not safe in directory names.
fn sanitize_cert_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect()
}
