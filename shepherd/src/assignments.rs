#![allow(dead_code)]

use anyhow::{Context, Result};
use std::path::Path;
use std::time::SystemTime;

use crate::types::ManagedAssignment;

#[derive(Debug, Deserialize)]
struct AssignmentsFile {
    #[serde(default)]
    assignments: Vec<ManagedAssignment>,
}
use serde::Deserialize;

pub fn load_assignments(path: &Path) -> Result<Vec<ManagedAssignment>> {
    if !path.exists() {
        return Ok(vec![]);
    }
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Reading assignments: {}", path.display()))?;
    let mut file: AssignmentsFile = serde_json::from_str(&content)
        .with_context(|| format!("Parsing assignments: {}", path.display()))?;
    for a in &mut file.assignments {
        if a.cert_name.is_empty() {
            a.cert_name = a.domain.clone().unwrap_or_default();
        }
    }
    Ok(file.assignments)
}

pub fn file_mtime(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).ok()?.modified().ok()
}
