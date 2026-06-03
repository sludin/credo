/// Unix file permission and ownership helpers.
use anyhow::{Context, Result};
use std::path::Path;

/// Parse an octal mode string: "600", "0640", "0o755" → u32.
pub fn parse_mode_octal(s: &str) -> Result<u32> {
    let cleaned = s.trim().trim_start_matches("0o").trim_start_matches('0');
    // Handle "0" → 0
    let cleaned = if cleaned.is_empty() { "0" } else { cleaned };
    u32::from_str_radix(cleaned, 8)
        .with_context(|| format!("Invalid octal mode: {}", s))
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
        let uid = owner.map(|name| {
            nix::unistd::User::from_name(name)
                .ok()
                .flatten()
                .map(|u| u.uid)
        }).flatten();

        let gid = group.map(|name| {
            nix::unistd::Group::from_name(name)
                .ok()
                .flatten()
                .map(|g| g.gid)
        }).flatten();

        nix::unistd::chown(path, uid, gid)
            .with_context(|| format!("chown {}:{} {}", owner.unwrap_or("-"), group.unwrap_or("-"), path.display()))?;
    }

    Ok(())
}
