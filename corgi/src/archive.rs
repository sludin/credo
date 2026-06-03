use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use crate::config::FlockEntry;

// ---------------------------------------------------------------------------
// Ordinal helpers
// ---------------------------------------------------------------------------

pub fn ordinal_string(n: u32) -> String {
    format!("{:03}", n)
}

/// Finds the next ordinal number to use in the archive directory for a cert name.
/// Scans for files matching `*-NNN.pem` and returns max+1 (minimum 1).
pub fn next_archive_ordinal(archive_cert_dir: &Path) -> Result<u32> {
    if !archive_cert_dir.exists() {
        return Ok(1);
    }
    let mut max = 0u32;
    for entry in fs::read_dir(archive_cert_dir).context("Reading archive dir")? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if let Some(n) = extract_ordinal(&name) {
            if n > max {
                max = n;
            }
        }
    }
    Ok(max + 1)
}

fn extract_ordinal(filename: &str) -> Option<u32> {
    let without_ext = filename.strip_suffix(".pem")?;
    without_ext.rsplit('-').next()?.parse().ok()
}

// ---------------------------------------------------------------------------
// Directory layout helpers
// ---------------------------------------------------------------------------

pub fn archive_dir(cert_store_dir: &Path, cert_name: &str) -> PathBuf {
    cert_store_dir.join("archive").join(cert_name)
}

pub fn live_dir(cert_store_dir: &Path, cert_name: &str) -> PathBuf {
    cert_store_dir.join("live").join(cert_name)
}

pub fn ensure_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Creating directory {}", parent.display()))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Atomic symlink replacement
// ---------------------------------------------------------------------------

/// Atomically replace (or create) a symlink at `link_path` pointing to `target`.
/// Uses a rename of a temp symlink to make the operation atomic.
pub fn replace_symlink(link_path: &Path, target: &Path) -> Result<()> {
    ensure_parent(link_path)?;

    let tmp = link_path.with_extension("tmp-symlink");
    // Remove any existing tmp
    let _ = fs::remove_file(&tmp);

    std::os::unix::fs::symlink(target, &tmp)
        .with_context(|| format!("Creating temp symlink {}", tmp.display()))?;

    fs::rename(&tmp, link_path)
        .with_context(|| format!("Renaming symlink to {}", link_path.display()))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// File permissions
// ---------------------------------------------------------------------------

pub fn set_permissions(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("chmod {:o} {}", mode, path.display()))
}

pub fn set_owner(path: &Path, owner: Option<&str>, group: Option<&str>) -> Result<()> {
    use nix::unistd::{chown, Group, User};

    let uid = if let Some(owner_str) = owner {
        User::from_name(owner_str)
            .with_context(|| format!("Looking up user '{}'", owner_str))?
            .map(|u| u.uid)
    } else {
        None
    };

    let gid = if let Some(group_str) = group {
        Group::from_name(group_str)
            .with_context(|| format!("Looking up group '{}'", group_str))?
            .map(|g| g.gid)
    } else {
        None
    };

    if uid.is_some() || gid.is_some() {
        chown(path, uid, gid)
            .with_context(|| format!("chown {} {:?}:{:?}", path.display(), owner, group))?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Archive install: write versioned files + update live symlinks
// ---------------------------------------------------------------------------

#[allow(dead_code)]
pub struct ArchiveInstallPaths {
    pub cert_archive: PathBuf,
    pub fullchain_archive: Option<PathBuf>,
    pub chain_archive: Option<PathBuf>,
    pub key_archive: Option<PathBuf>,
}

pub fn install_to_archive(
    entry: &FlockEntry,
    cert_store_dir: &Path,
    cert_pem: &str,
    fullchain_pem: Option<&str>,
    chain_pem: Option<&str>,
    key_pem: Option<&str>,
) -> Result<ArchiveInstallPaths> {
    let archive = archive_dir(cert_store_dir, &entry.name);
    let live = live_dir(cert_store_dir, &entry.name);

    fs::create_dir_all(&archive).context("Creating archive dir")?;
    fs::create_dir_all(&live).context("Creating live dir")?;

    let ord = next_archive_ordinal(&archive)?;
    let sfx = ordinal_string(ord);

    // Write cert
    let cert_archive_path = archive.join(format!("cert-{}.pem", sfx));
    write_file(&cert_archive_path, cert_pem.as_bytes(), entry.cert_mode.unwrap_or(0o644))?;
    if entry.cert_owner.is_some() || entry.cert_group.is_some() {
        set_owner(&cert_archive_path, entry.cert_owner.as_deref(), entry.cert_group.as_deref()).ok();
    }

    // Update live/cert.pem symlink
    let live_cert = live.join("cert.pem");
    let rel_cert = pathdiff(&cert_archive_path, &live_cert);
    replace_symlink(&live_cert, &rel_cert)?;
    // Also update the canonical cert path from config
    if entry.path != live_cert {
        ensure_parent(&entry.path)?;
        replace_symlink(&entry.path, &cert_archive_path)?;
    }

    // Write fullchain
    let fullchain_archive_path = fullchain_pem.map(|fc| {
        let p = archive.join(format!("fullchain-{}.pem", sfx));
        write_file(&p, fc.as_bytes(), entry.cert_mode.unwrap_or(0o644)).ok();
        if entry.cert_owner.is_some() || entry.cert_group.is_some() {
            set_owner(&p, entry.cert_owner.as_deref(), entry.cert_group.as_deref()).ok();
        }
        p
    });

    if let Some(ref fc_path) = fullchain_archive_path {
        let live_fc = live.join("fullchain.pem");
        let rel = pathdiff(fc_path, &live_fc);
        replace_symlink(&live_fc, &rel)?;
        if let Some(ref configured) = entry.fullchain_path {
            if configured != &live_fc {
                ensure_parent(configured)?;
                replace_symlink(configured, fc_path)?;
            }
        }
    }

    // Write chain
    let chain_archive_path = chain_pem.map(|ch| {
        let p = archive.join(format!("chain-{}.pem", sfx));
        write_file(&p, ch.as_bytes(), entry.cert_mode.unwrap_or(0o644)).ok();
        p
    });

    if let Some(ref ch_path) = chain_archive_path {
        let live_ch = live.join("chain.pem");
        let rel = pathdiff(ch_path, &live_ch);
        replace_symlink(&live_ch, &rel)?;
        if let Some(ref configured) = entry.chain_path {
            if configured != &live_ch {
                ensure_parent(configured)?;
                replace_symlink(configured, ch_path)?;
            }
        }
    }

    // Write key
    let key_archive_path = key_pem.map(|k| {
        let p = archive.join(format!("privkey-{}.pem", sfx));
        write_file(&p, k.as_bytes(), entry.key_mode.unwrap_or(0o640)).ok();
        if entry.key_owner.is_some() || entry.key_group.is_some() {
            set_owner(&p, entry.key_owner.as_deref(), entry.key_group.as_deref()).ok();
        }
        p
    });

    if let Some(ref key_path) = key_archive_path {
        let live_key = live.join("privkey.pem");
        let rel = pathdiff(key_path, &live_key);
        replace_symlink(&live_key, &rel)?;
        if entry.key_path != live_key {
            ensure_parent(&entry.key_path)?;
            replace_symlink(&entry.key_path, key_path)?;
        }
        // Key permissions
        set_permissions(&entry.key_path, entry.key_mode.unwrap_or(0o640))?;
        if entry.key_owner.is_some() || entry.key_group.is_some() {
            set_owner(&entry.key_path, entry.key_owner.as_deref(), entry.key_group.as_deref()).ok();
        }
    }

    Ok(ArchiveInstallPaths {
        cert_archive: cert_archive_path,
        fullchain_archive: fullchain_archive_path,
        chain_archive: chain_archive_path,
        key_archive: key_archive_path,
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn write_file(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    ensure_parent(path)?;
    fs::write(path, data).with_context(|| format!("Writing {}", path.display()))?;
    set_permissions(path, mode)?;
    Ok(())
}

/// Compute a relative path from `target` to `link_path`'s directory.
/// Falls back to absolute `target` if diff can't be computed.
fn pathdiff(target: &Path, link_path: &Path) -> PathBuf {
    let link_dir = link_path.parent().unwrap_or(Path::new("."));
    // Simple implementation: count common prefix
    let target_comps: Vec<_> = target.components().collect();
    let link_comps: Vec<_> = link_dir.components().collect();

    let common_len = target_comps
        .iter()
        .zip(link_comps.iter())
        .take_while(|(a, b)| a == b)
        .count();

    let up_count = link_comps.len() - common_len;
    let mut rel = PathBuf::new();
    for _ in 0..up_count {
        rel.push("..");
    }
    for comp in &target_comps[common_len..] {
        rel.push(comp);
    }
    if rel.as_os_str().is_empty() {
        target.to_path_buf()
    } else {
        rel
    }
}
