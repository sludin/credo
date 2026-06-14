use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use crate::config::FlockEntry;
pub use credo_lib::archive::{next_archive_ordinal, ordinal_string, replace_symlink};

// ---------------------------------------------------------------------------
// Directory layout helpers
// ---------------------------------------------------------------------------

pub fn archive_dir(cert_store_dir: &Path, cert_name: &str) -> PathBuf {
    cert_store_dir.join("archive").join(cert_name)
}

pub fn live_dir(cert_store_dir: &Path, cert_name: &str) -> PathBuf {
    cert_store_dir.join("live").join(cert_name)
}

/// Staging path for a private key while its CSR is in flight.
/// Keyed by cert name; cleared when the cert arrives via install_to_archive.
pub fn pending_key_path(cert_store_dir: &Path, cert_name: &str) -> PathBuf {
    cert_store_dir
        .join("pending")
        .join(format!("{}.pem", cert_name))
}

pub fn ensure_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Creating directory {}", parent.display()))?;
    }
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

    let gid = if let Some(group_str) = group {
        let g = Group::from_name(group_str)
            .with_context(|| format!("Looking up group '{}'", group_str))?
            .with_context(|| format!("Group '{}' not found", group_str))?;
        Some(g.gid)
    } else {
        None
    };

    let uid = if let Some(owner_str) = owner {
        use std::os::unix::fs::MetadataExt;
        let target = User::from_name(owner_str)
            .with_context(|| format!("Looking up user '{}'", owner_str))?
            .map(|u| u.uid);
        let current_uid = std::fs::metadata(path).map(|m| m.uid()).unwrap_or(u32::MAX);
        target.filter(|u| u.as_raw() != current_uid)
    } else {
        None
    };

    if uid.is_some() || gid.is_some() {
        chown(path, uid, gid).with_context(|| {
            format!(
                "chown {}:{} {}",
                owner.unwrap_or("-"),
                group.unwrap_or("-"),
                path.display()
            )
        })?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Archive install: write versioned files + update live symlinks
// ---------------------------------------------------------------------------

pub fn install_to_archive(
    entry: &FlockEntry,
    cert_store_dir: &Path,
    cert_pem: &str,
    fullchain_pem: Option<&str>,
    chain_pem: Option<&str>,
    key_pem: Option<&str>,
) -> Result<()> {
    let archive = archive_dir(cert_store_dir, &entry.name);
    let live = live_dir(cert_store_dir, &entry.name);

    fs::create_dir_all(&archive).context("Creating archive dir")?;
    fs::create_dir_all(&live).context("Creating live dir")?;

    let ord = next_archive_ordinal(&archive)?;
    let sfx = ordinal_string(ord);

    // Write cert
    let cert_archive_path = archive.join(format!("cert-{}.pem", sfx));
    write_file(
        &cert_archive_path,
        cert_pem.as_bytes(),
        entry.cert_mode.unwrap_or(0o644),
    )?;
    if entry.cert_owner.is_some() || entry.cert_group.is_some() {
        if let Err(e) = set_owner(
            &cert_archive_path,
            entry.cert_owner.as_deref(),
            entry.cert_group.as_deref(),
        ) {
            tracing::warn!(path = %cert_archive_path.display(), error = %e, "Failed to apply cert ownership");
        }
    }

    // Update live/cert.pem symlink
    let live_cert = live.join("cert.pem");
    let live_fc = live.join("fullchain.pem");
    let rel_cert = pathdiff(&cert_archive_path, &live_cert);
    replace_symlink(&rel_cert, &live_cert)?;
    // Update the canonical cert path only when it is not also the fullchain path.
    // When entry.path == live_fc, the fullchain section below manages that symlink;
    // creating it here (pointing at cert-NNN.pem) would leave it wrong if
    // fullchain_pem is None.
    if entry.path != live_cert && entry.path != live_fc {
        ensure_parent(&entry.path)?;
        replace_symlink(&pathdiff(&cert_archive_path, &entry.path), &entry.path)?;
    }

    // Write fullchain
    let fullchain_archive_path: Option<PathBuf> = if let Some(fc) = fullchain_pem {
        let p = archive.join(format!("fullchain-{}.pem", sfx));
        write_file(&p, fc.as_bytes(), entry.cert_mode.unwrap_or(0o644))?;
        if entry.cert_owner.is_some() || entry.cert_group.is_some() {
            if let Err(e) = set_owner(&p, entry.cert_owner.as_deref(), entry.cert_group.as_deref()) {
                tracing::warn!(path = %p.display(), error = %e, "Failed to apply fullchain ownership");
            }
        }
        Some(p)
    } else {
        None
    };

    if let Some(ref fc_path) = fullchain_archive_path {
        let rel = pathdiff(fc_path, &live_fc);
        replace_symlink(&rel, &live_fc)?;
        if let Some(ref configured) = entry.fullchain_path {
            if configured != &live_fc {
                ensure_parent(configured)?;
                replace_symlink(&pathdiff(fc_path, configured), configured)?;
            }
        }
    }

    // Write chain
    let chain_archive_path: Option<PathBuf> = if let Some(ch) = chain_pem {
        let p = archive.join(format!("chain-{}.pem", sfx));
        write_file(&p, ch.as_bytes(), entry.cert_mode.unwrap_or(0o644))?;
        Some(p)
    } else {
        None
    };

    if let Some(ref ch_path) = chain_archive_path {
        let live_ch = live.join("chain.pem");
        let rel = pathdiff(ch_path, &live_ch);
        replace_symlink(&rel, &live_ch)?;
        if let Some(ref configured) = entry.chain_path {
            if configured != &live_ch {
                ensure_parent(configured)?;
                replace_symlink(&pathdiff(ch_path, configured), configured)?;
            }
        }
    }

    // Write key — either provided directly by the caller, or picked up from the
    // pending staging area where generate_key_and_csr wrote it while the CSR was
    // in flight.  All real key files live in archive/; live/ only ever holds symlinks.
    let key_archive_path = if let Some(k) = key_pem {
        let p = archive.join(format!("privkey-{}.pem", sfx));
        write_file(&p, k.as_bytes(), entry.key_mode.unwrap_or(0o640))?;
        if entry.key_owner.is_some() || entry.key_group.is_some() {
            if let Err(e) = set_owner(&p, entry.key_owner.as_deref(), entry.key_group.as_deref()) {
                tracing::warn!(path = %p.display(), error = %e, "Failed to apply key ownership");
            }
        }
        Some(p)
    } else {
        let pending = pending_key_path(cert_store_dir, &entry.name);
        if pending.exists() {
            let key_bytes = fs::read(&pending)
                .with_context(|| format!("Reading pending key {}", pending.display()))?;
            let p = archive.join(format!("privkey-{}.pem", sfx));
            write_file(&p, &key_bytes, entry.key_mode.unwrap_or(0o640))?;
            if entry.key_owner.is_some() || entry.key_group.is_some() {
                if let Err(e) =
                    set_owner(&p, entry.key_owner.as_deref(), entry.key_group.as_deref())
                {
                    tracing::warn!(path = %p.display(), error = %e, "Failed to apply key ownership");
                }
            }
            let _ = fs::remove_file(&pending); // key is now safely in archive
            Some(p)
        } else {
            None
        }
    };

    if let Some(ref key_path) = key_archive_path {
        let live_key = live.join("privkey.pem");
        let rel = pathdiff(key_path, &live_key);
        replace_symlink(&rel, &live_key)?;
        if entry.key_path != live_key {
            ensure_parent(&entry.key_path)?;
            replace_symlink(&pathdiff(key_path, &entry.key_path), &entry.key_path)?;
        }
        // Key permissions
        set_permissions(&entry.key_path, entry.key_mode.unwrap_or(0o640))?;
        if entry.key_owner.is_some() || entry.key_group.is_some() {
            if let Err(e) = set_owner(
                &entry.key_path,
                entry.key_owner.as_deref(),
                entry.key_group.as_deref(),
            ) {
                tracing::warn!(path = %entry.key_path.display(), error = %e, "Failed to apply key ownership");
            }
        }
    }

    Ok(())
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
