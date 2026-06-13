use anyhow::{Context, Result};
use std::path::Path;
use std::time::SystemTime;

use crate::types::ManagedAssignment;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct AssignmentsFile {
    #[serde(default)]
    assignments: Vec<ManagedAssignment>,
}

pub fn load_assignments(path: &Path) -> Result<Vec<ManagedAssignment>> {
    if !path.exists() {
        return Ok(vec![]);
    }
    let value = credo_lib::config::load_json_config(path)
        .with_context(|| format!("Loading assignments config: {}", path.display()))?;
    let mut file: AssignmentsFile = serde_json::from_value(value)
        .with_context(|| format!("Parsing assignments: {}", path.display()))?;
    for a in &mut file.assignments {
        if a.cert_name.is_empty() {
            a.cert_name = a.domain.clone().unwrap_or_default();
        }
    }
    Ok(file.assignments)
}

pub fn save_assignments(path: &Path, assignments: &[ManagedAssignment]) -> Result<()> {
    let file = AssignmentsFile {
        assignments: assignments.to_vec(),
    };
    let content = serde_json::to_string_pretty(&file).context("Serializing assignments")?;
    std::fs::write(path, content)
        .with_context(|| format!("Writing assignments: {}", path.display()))
}

pub fn file_mtime(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).ok()?.modified().ok()
}
