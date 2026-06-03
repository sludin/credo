/// Config loading utilities shared by all credo Rust services.
///
/// Each service's `load_config()` calls these helpers for interpolation,
/// include resolution, path handling, and type coercion. Service-specific
/// config structs live in each service's own crate.
use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Variable interpolation
// ---------------------------------------------------------------------------

/// Replace `${VAR}` placeholders in `s` using `vars`. Single pass — callers
/// invoke until stable when chained references are expected.
pub fn interpolate(s: &str, vars: &HashMap<String, String>) -> String {
    let mut result = s.to_string();
    for (k, v) in vars {
        result = result.replace(&format!("${{{}}}", k), v);
    }
    result
}

/// Build a fully-resolved variable map from the config `vars` block.
///
/// Phase 1: sequential pass — each var is resolved against previously-inserted
/// vars, so `b = "${a}/bar"` works when `a` is declared first.
///
/// Phase 2: convergence loop — iterate the whole map until no value changes.
/// Handles forward references without an arbitrary iteration limit. Circular
/// references (e.g. `a = "${b}"`, `b = "${a}"`) collapse to stable self-
/// referential strings on the first pass and never loop. Unresolvable `${...}`
/// patterns survive as literals and will produce clear errors at path resolution.
pub fn collect_vars(raw: &serde_json::Value) -> HashMap<String, String> {
    let mut map = HashMap::new();

    if let Some(obj) = raw.get("vars").and_then(|v| v.as_object()) {
        for (k, v) in obj {
            let raw_str = match v {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            let resolved = interpolate(&raw_str, &map);
            map.insert(k.clone(), resolved);
        }
    }

    loop {
        let snapshot = map.clone();
        for val in map.values_mut() {
            *val = interpolate(val, &snapshot);
        }
        if map == snapshot {
            break;
        }
    }

    map
}

/// Recursively replace `${VAR}` in all string values of a JSON tree.
pub fn interpolate_json(
    value: &serde_json::Value,
    vars: &HashMap<String, String>,
) -> serde_json::Value {
    match value {
        serde_json::Value::String(s) => serde_json::Value::String(interpolate(s, vars)),
        serde_json::Value::Object(obj) => {
            let mut new_obj = serde_json::Map::new();
            for (k, v) in obj {
                new_obj.insert(k.clone(), interpolate_json(v, vars));
            }
            serde_json::Value::Object(new_obj)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(|v| interpolate_json(v, vars)).collect())
        }
        other => other.clone(),
    }
}

// ---------------------------------------------------------------------------
// Deep merge (include resolution)
// ---------------------------------------------------------------------------

/// Recursively merge `overlay` into `base`. Objects are merged key-by-key;
/// all other types are replaced. The main config overlays on top of includes.
pub fn deep_merge(base: &mut serde_json::Value, overlay: &serde_json::Value) {
    match (base, overlay) {
        (serde_json::Value::Object(base_map), serde_json::Value::Object(overlay_map)) => {
            for (k, v) in overlay_map {
                let entry = base_map.entry(k.clone()).or_insert(serde_json::Value::Null);
                deep_merge(entry, v);
            }
        }
        (base, overlay) => *base = overlay.clone(),
    }
}

/// Process the `includes` array in `value`, load each file relative to
/// `config_path`, deep-merge them as the base, then overlay the main config.
/// `seen` tracks canonical paths to detect circular includes.
pub fn resolve_includes(
    mut value: serde_json::Value,
    config_path: &Path,
    seen: &mut Vec<PathBuf>,
) -> Result<serde_json::Value> {
    let includes: Vec<String> = match value.get("includes").and_then(|v| v.as_array()) {
        Some(arr) => arr.iter().filter_map(|v| v.as_str().map(str::to_string)).collect(),
        None      => return Ok(value),
    };

    for include_str in includes {
        let include_path = if Path::new(&include_str).is_absolute() {
            PathBuf::from(&include_str)
        } else {
            config_path.parent().unwrap_or(Path::new(".")).join(&include_str)
        };

        let canonical = include_path.canonicalize().unwrap_or(include_path.clone());
        if seen.contains(&canonical) {
            bail!("Circular include: {}", include_path.display());
        }
        seen.push(canonical);

        let content = std::fs::read_to_string(&include_path)
            .with_context(|| format!("Reading include: {}", include_path.display()))?;
        let included: serde_json::Value = serde_json::from_str(&content)
            .with_context(|| format!("Parsing include: {}", include_path.display()))?;
        let included = resolve_includes(included, &include_path, seen)?;

        let mut merged = included;
        deep_merge(&mut merged, &value);
        value = merged;
    }

    Ok(value)
}

// ---------------------------------------------------------------------------
// Path resolution
// ---------------------------------------------------------------------------

/// Resolve `raw` relative to `base`; absolute paths are returned unchanged.
pub fn resolve_path(base: &Path, raw: &str) -> PathBuf {
    let p = Path::new(raw);
    if p.is_absolute() { p.to_path_buf() } else { base.join(p) }
}

/// Resolve an optional path string against `base`, returning `None` if missing.
pub fn resolve_path_opt(base: &Path, raw: Option<&str>) -> Option<PathBuf> {
    raw.map(|s| resolve_path(base, s))
}

/// Resolve with a fallback default string.
pub fn resolve_path_or(base: &Path, raw: Option<&str>, fallback: &str) -> PathBuf {
    resolve_path(base, raw.unwrap_or(fallback))
}

// ---------------------------------------------------------------------------
// Type coercion helpers (used in load_config implementations)
// ---------------------------------------------------------------------------

pub fn bool_from_value(v: &serde_json::Value, fallback: bool) -> bool {
    match v {
        serde_json::Value::Bool(b)   => *b,
        serde_json::Value::String(s) => matches!(s.as_str(), "true" | "1" | "yes" | "on"),
        serde_json::Value::Number(n) => n.as_i64().map(|n| n != 0).unwrap_or(fallback),
        _ => fallback,
    }
}

pub fn u64_from_value(v: &serde_json::Value, fallback: u64) -> u64 {
    match v {
        serde_json::Value::Number(n) => n.as_u64().unwrap_or(fallback),
        serde_json::Value::String(s) => s.parse().unwrap_or(fallback),
        _ => fallback,
    }
}

pub fn str_from_env(env_key: &str, fallback: &str) -> String {
    std::env::var(env_key).unwrap_or_else(|_| fallback.to_string())
}

pub fn bool_from_env(env_key: &str, fallback: bool) -> bool {
    match std::env::var(env_key).as_deref() {
        Ok("1" | "true" | "yes" | "on")   => true,
        Ok("0" | "false" | "no" | "off")  => false,
        _ => fallback,
    }
}

pub fn u64_from_env(env_key: &str, fallback: u64) -> u64 {
    std::env::var(env_key).ok().and_then(|s| s.parse().ok()).unwrap_or(fallback)
}

pub fn u16_from_env(env_key: &str, fallback: u16) -> u16 {
    std::env::var(env_key).ok().and_then(|s| s.parse().ok()).unwrap_or(fallback)
}

// ---------------------------------------------------------------------------
// Unknown-field guard (JSON comment-out convention)
// ---------------------------------------------------------------------------

/// Recursively remove all object keys that start with `_`.
///
/// This implements the JSON comment-out convention: `_fieldName` is silently
/// ignored, giving config authors a way to disable entries without deleting
/// them.  Call this AFTER interpolation but BEFORE deserializing into a typed
/// struct with `#[serde(deny_unknown_fields)]`.
pub fn strip_underscore_keys(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            map.retain(|k, _| !k.starts_with('_'));
            for v in map.values_mut() {
                strip_underscore_keys(v);
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr.iter_mut() {
                strip_underscore_keys(v);
            }
        }
        _ => {}
    }
}
