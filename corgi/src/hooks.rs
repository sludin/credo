use anyhow::Result;
use regex::Regex;
use std::collections::HashSet;
use std::process::Stdio;
use tokio::process::Command;

use crate::config::{CorgiConfig, FlockEntry, ServiceHookDef};
use crate::types::HookRef;

#[derive(Debug, Clone)]
pub struct HookResult {
    pub hook: String,
    pub command: String,
    pub stdout: String,
    pub stderr: String,
}

/// Execute all hooks for a flock entry (defaultHooks + entry hooks), deduplicated.
pub async fn run_hooks(entry: &FlockEntry, config: &CorgiConfig) -> Vec<HookResult> {
    let mut all_refs: Vec<HookRef> = config.default_hooks.clone();
    all_refs.extend(entry.hooks.clone());

    // Deduplicate by (name, args) serialized key
    let mut seen = HashSet::new();
    let mut deduped: Vec<HookRef> = vec![];
    for r in all_refs {
        let key = match &r {
            HookRef::Simple(s) => s.clone(),
            HookRef::Parameterized { name, args } => {
                let mut pairs: Vec<_> = args.iter().collect();
                pairs.sort_by_key(|(k, _)| *k);
                format!(
                    "{}:{}",
                    name,
                    serde_json::to_string(&pairs).unwrap_or_default()
                )
            }
        };
        if seen.insert(key) {
            deduped.push(r);
        }
    }

    let mut results = vec![];

    for hook_ref in deduped {
        let hook_name = hook_ref.name().to_string();
        let hook_def = match config.service_hooks.get(&hook_name) {
            Some(d) => d,
            None => {
                tracing::warn!(
                    hook = %hook_name,
                    cert_name = %entry.name,
                    "Hook not found in serviceHooks; skipping"
                );
                continue;
            }
        };

        match hook_def {
            ServiceHookDef::Parameterized {
                exec,
                args: arg_specs,
            } => {
                let supplied_args = hook_ref.args();

                // Validate args
                let mut valid = true;
                for (arg_name, spec) in arg_specs {
                    let value = match supplied_args.get(arg_name) {
                        Some(v) => v,
                        None => {
                            tracing::warn!(
                                hook = %hook_name,
                                arg = %arg_name,
                                cert_name = %entry.name,
                                "Parameterized hook missing required arg; skipping"
                            );
                            valid = false;
                            break;
                        }
                    };

                    let pattern_str = spec.kind.pattern();
                    let re = match Regex::new(pattern_str) {
                        Ok(r) => r,
                        Err(_) => {
                            valid = false;
                            break;
                        }
                    };
                    if !re.is_match(value) {
                        tracing::warn!(
                            hook = %hook_name,
                            arg = %arg_name,
                            cert_name = %entry.name,
                            "Parameterized hook arg failed validation; skipping"
                        );
                        valid = false;
                        break;
                    }
                }
                if !valid {
                    continue;
                }

                // Substitute placeholders
                let argv: Vec<String> = exec
                    .iter()
                    .map(|token| {
                        // Replace {placeholder} with validated arg value
                        let mut t = token.clone();
                        for (k, v) in &supplied_args {
                            t = t.replace(&format!("{{{}}}", k), v);
                        }
                        t
                    })
                    .collect();

                let command_str = argv.join(" ");

                match spawn_no_shell(&argv).await {
                    Ok((stdout, stderr)) => {
                        results.push(HookResult {
                            hook: hook_name,
                            command: command_str,
                            stdout,
                            stderr,
                        });
                    }
                    Err(e) => {
                        tracing::warn!(
                            hook = %hook_name,
                            command = %command_str,
                            error = %e,
                            cert_name = %entry.name,
                            "Parameterized hook failed"
                        );
                        results.push(HookResult {
                            hook: hook_name,
                            command: command_str,
                            stdout: String::new(),
                            stderr: e.to_string(),
                        });
                    }
                }
            }

            ServiceHookDef::Simple(commands) => {
                for cmd_str in commands {
                    match spawn_shell(cmd_str).await {
                        Ok((stdout, stderr)) => {
                            results.push(HookResult {
                                hook: hook_name.clone(),
                                command: cmd_str.clone(),
                                stdout,
                                stderr,
                            });
                        }
                        Err(e) => {
                            tracing::warn!(
                                hook = %hook_name,
                                command = %cmd_str,
                                error = %e,
                                cert_name = %entry.name,
                                "Simple hook failed; aborting remaining commands in hook"
                            );
                            results.push(HookResult {
                                hook: hook_name.clone(),
                                command: cmd_str.clone(),
                                stdout: String::new(),
                                stderr: e.to_string(),
                            });
                            break;
                        }
                    }
                }
            }
        }
    }

    results
}

/// Spawn a command with shell (for simple hooks).
async fn spawn_shell(cmd: &str) -> Result<(String, String)> {
    let output = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        return Err(anyhow::anyhow!(
            "exited with {:?}: {}",
            output.status.code(),
            stderr.trim().to_string() + &stdout
        ));
    }

    Ok((
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    ))
}

/// Spawn a command without shell (for parameterized hooks — prevents injection).
async fn spawn_no_shell(argv: &[String]) -> Result<(String, String)> {
    if argv.is_empty() {
        return Err(anyhow::anyhow!("Empty command"));
    }
    let output = Command::new(&argv[0])
        .args(&argv[1..])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        return Err(anyhow::anyhow!(
            "exited with {:?}: {}",
            output.status.code(),
            stderr.trim().to_string() + &stdout
        ));
    }

    Ok((
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    ))
}

/// Validate hook definitions at startup (warn on issues, don't panic).
pub fn validate_hooks(config: &CorgiConfig) {
    let placeholder_re = Regex::new(r"\{([^}]+)\}").unwrap();
    for (hook_name, hook_def) in &config.service_hooks {
        if let ServiceHookDef::Parameterized { exec, args } = hook_def {
            let mut placeholders = HashSet::new();
            for token in exec {
                for cap in placeholder_re.captures_iter(token.as_str()) {
                    placeholders.insert(cap[1].to_string());
                }
            }
            let declared: HashSet<_> = args.keys().cloned().collect();
            let undeclared: Vec<_> = placeholders.difference(&declared).collect();
            let unused: Vec<_> = declared.difference(&placeholders).collect();
            if !undeclared.is_empty() {
                tracing::warn!(hook = %hook_name, ?undeclared, "Hook placeholders not declared in args");
            }
            if !unused.is_empty() {
                tracing::warn!(hook = %hook_name, ?unused, "Hook args declared but no placeholder in exec");
            }
        }
    }

    // Check all referenced hook names exist
    let all_refs: Vec<_> = config
        .default_hooks
        .iter()
        .chain(config.flock.iter().flat_map(|e| e.hooks.iter()))
        .map(|r| r.name().to_string())
        .collect();

    for name in &all_refs {
        if !config.service_hooks.contains_key(name.as_str()) {
            tracing::warn!(hook = %name, "Referenced hook not defined in serviceHooks");
        }
    }
}
