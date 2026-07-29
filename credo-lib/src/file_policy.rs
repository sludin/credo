/// Unix file permission and ownership helpers.
use anyhow::{Context, Result};
use std::path::Path;

/// Write `data` to `path`, creating the file with `mode` already in effect
/// from the moment it exists on disk — unlike `fs::write` followed by
/// `set_permissions`/`apply_file_policy`, there is no window where the file
/// sits at the default umask (typically world-readable) before permissions
/// are tightened. Use this for any sensitive file (private keys in
/// particular) instead of write-then-chmod.
///
/// If `path` already exists, the `mode` open flag has no effect (Unix only
/// applies it when `O_CREAT` actually creates the file), so permissions are
/// also set explicitly afterward via the open file descriptor — by that
/// point the content is already written, so this doesn't reopen a
/// world-readable window, it just guards against a pre-existing file having
/// stale, looser permissions from some earlier write.
pub fn write_file_with_mode(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(path)
        .with_context(|| format!("Opening {} for write", path.display()))?;
    file.write_all(data)
        .with_context(|| format!("Writing {}", path.display()))?;
    file.set_permissions(std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("chmod {:o} {}", mode, path.display()))?;
    Ok(())
}

/// Parse an octal mode string: "600", "0640", "0o755" → u32.
pub fn parse_mode_octal(s: &str) -> Result<u32> {
    let cleaned = s.trim().trim_start_matches("0o").trim_start_matches('0');
    // Handle "0" → 0
    let cleaned = if cleaned.is_empty() { "0" } else { cleaned };
    u32::from_str_radix(cleaned, 8).with_context(|| format!("Invalid octal mode: {}", s))
}

/// Set file permissions and optionally ownership.
/// `owner` and `group` accept username/groupname strings.
pub fn apply_file_policy(
    path: &Path,
    mode: Option<u32>,
    owner: Option<&str>,
    group: Option<&str>,
) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    if let Some(m) = mode {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(m))
            .with_context(|| format!("chmod {:o} {}", m, path.display()))?;
    }

    if owner.is_some() || group.is_some() {
        let uid = owner.and_then(|name| {
            nix::unistd::User::from_name(name)
                .ok()
                .flatten()
                .map(|u| u.uid)
        });

        let gid = group.and_then(|name| {
            nix::unistd::Group::from_name(name)
                .ok()
                .flatten()
                .map(|g| g.gid)
        });

        // Passing any non-(-1) uid to chown(2) requires CAP_CHOWN even when the
        // uid would not change. Skip the uid arg when the file already has the
        // right owner so unprivileged processes can still chgrp their own files.
        let effective_uid = if let Some(target_uid) = uid {
            use std::os::unix::fs::MetadataExt;
            let current_uid = std::fs::metadata(path).map(|m| m.uid()).unwrap_or(u32::MAX);
            if current_uid == target_uid.as_raw() {
                None
            } else {
                Some(target_uid)
            }
        } else {
            None
        };

        nix::unistd::chown(path, effective_uid, gid).with_context(|| {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// The file has exactly the requested mode immediately after creation —
    /// no intermediate default-umask permissions ever apply.
    #[test]
    fn write_file_with_mode_sets_requested_mode_on_new_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("secret.pem");

        write_file_with_mode(&path, b"private key material", 0o600).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(std::fs::read(&path).unwrap(), b"private key material");
    }

    /// Regression guard for the exact bug being fixed: this function must
    /// never rely on a separate fs::write + set_permissions pair — a
    /// pre-existing file's permissions must be tightened rather than left at
    /// whatever they were from an earlier, looser write.
    #[test]
    fn write_file_with_mode_tightens_permissions_on_existing_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("secret.pem");

        // Simulate a file that was previously created world-readable.
        std::fs::write(&path, b"old content").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        write_file_with_mode(&path, b"new private key material", 0o600).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "rewriting an existing looser-permissioned file must still tighten its mode"
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"new private key material");
    }

    #[test]
    fn parse_mode_octal_handles_common_forms() {
        assert_eq!(parse_mode_octal("600").unwrap(), 0o600);
        assert_eq!(parse_mode_octal("0640").unwrap(), 0o640);
        assert_eq!(parse_mode_octal("0o755").unwrap(), 0o755);
    }
}
