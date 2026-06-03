use anyhow::Result;
use serde_json::{json, Value};
use std::io::Write;
use std::path::Path;

/// Append one JSON line to the Certificate Transparency log.
/// Opens in append mode on every call — cheap and correct for an audit log.
pub fn append_ct_log(path: &Path, action: &str, actor: &str, details: Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let entry = json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "action": action,
        "actor": actor,
        "details": details,
    });

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;

    writeln!(file, "{}", serde_json::to_string(&entry)?)?;
    Ok(())
}
