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
    pub success: bool,
    pub exit_code: Option<i32>,
}

/// Raw outcome of spawning a hook command — distinct from `Err` (the command
/// never ran at all, e.g. binary not found) so a non-zero exit can carry its
/// own stdout/stderr/code instead of being flattened into an error string.
struct SpawnOutput {
    stdout: String,
    stderr: String,
    success: bool,
    exit_code: Option<i32>,
}

/// Execute all hooks for a flock entry.
/// Uses entry.hooks when set; falls back to config.default_hooks when None.
async fn run_hooks(entry: &FlockEntry, config: &CorgiConfig) -> Vec<HookResult> {
    let refs: &[HookRef] = match &entry.hooks {
        Some(h) => h,
        None => &config.default_hooks,
    };

    let mut results = vec![];

    for hook_ref in refs {
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
                    Ok(out) => {
                        results.push(HookResult {
                            hook: hook_name,
                            command: command_str,
                            stdout: out.stdout,
                            stderr: out.stderr,
                            success: out.success,
                            exit_code: out.exit_code,
                        });
                    }
                    Err(e) => {
                        results.push(HookResult {
                            hook: hook_name,
                            command: command_str,
                            stdout: String::new(),
                            stderr: e.to_string(),
                            success: false,
                            exit_code: None,
                        });
                    }
                }
            }

            ServiceHookDef::Simple(commands) => {
                for cmd_str in commands {
                    match spawn_shell(cmd_str).await {
                        Ok(out) => {
                            let success = out.success;
                            results.push(HookResult {
                                hook: hook_name.clone(),
                                command: cmd_str.clone(),
                                stdout: out.stdout,
                                stderr: out.stderr,
                                success,
                                exit_code: out.exit_code,
                            });
                            // A non-zero exit aborts remaining commands in this
                            // hook, same as a command that failed to start.
                            if !success {
                                break;
                            }
                        }
                        Err(e) => {
                            results.push(HookResult {
                                hook: hook_name.clone(),
                                command: cmd_str.clone(),
                                stdout: String::new(),
                                stderr: e.to_string(),
                                success: false,
                                exit_code: None,
                            });
                            break;
                        }
                    }
                }
            }

            ServiceHookDef::CredoSignal { pid_file, signal } => {
                let command_str = format!("{:?} -> {}", signal, pid_file.display());
                match credo_lib::pid::signal(pid_file, *signal) {
                    Ok(()) => {
                        results.push(HookResult {
                            hook: hook_name,
                            command: command_str,
                            stdout: "signaled".to_string(),
                            stderr: String::new(),
                            success: true,
                            exit_code: None,
                        });
                    }
                    Err(e) => {
                        results.push(HookResult {
                            hook: hook_name,
                            command: command_str,
                            stdout: String::new(),
                            stderr: e.to_string(),
                            success: false,
                            exit_code: None,
                        });
                    }
                }
            }
        }
    }

    results
}

/// Run all hooks for a flock entry and log each execution.
/// This is the single entry point callers should use — `run_hooks` alone
/// does not log outcomes, which previously let call sites silently diverge
/// in observability.
///
/// A hook that exits non-zero (or fails to start) always logs at ERROR with
/// its stdout/stderr/exit code, regardless of config — that's the case
/// operators need to see. A hook that succeeds always logs an INFO "Hook
/// executed" line; its stdout/stderr are additionally included only when
/// `config.log_hook_output` is set, since successful output is noisy by
/// default.
pub async fn run_hooks_logged(entry: &FlockEntry, config: &CorgiConfig) -> Vec<HookResult> {
    let results = run_hooks(entry, config).await;
    for hr in &results {
        if !hr.success {
            tracing::error!(
                cert_name = %entry.name,
                hook = %hr.hook,
                command = %hr.command,
                exit_code = ?hr.exit_code,
                stdout = %hr.stdout,
                stderr = %hr.stderr,
                "Hook failed"
            );
        } else if config.log_hook_output {
            tracing::info!(
                cert_name = %entry.name,
                hook = %hr.hook,
                command = %hr.command,
                stdout = %hr.stdout,
                stderr = %hr.stderr,
                "Hook executed"
            );
        } else {
            tracing::info!(
                cert_name = %entry.name,
                hook = %hr.hook,
                command = %hr.command,
                "Hook executed"
            );
        }
    }
    results
}

/// Spawn a command with shell (for simple hooks).
async fn spawn_shell(cmd: &str) -> Result<SpawnOutput> {
    let output = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await?;

    Ok(SpawnOutput {
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        success: output.status.success(),
        exit_code: output.status.code(),
    })
}

/// Spawn a command without shell (for parameterized hooks — prevents injection).
async fn spawn_no_shell(argv: &[String]) -> Result<SpawnOutput> {
    if argv.is_empty() {
        return Err(anyhow::anyhow!("Empty command"));
    }
    let output = Command::new(&argv[0])
        .args(&argv[1..])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await?;

    Ok(SpawnOutput {
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        success: output.status.success(),
        exit_code: output.status.code(),
    })
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
        .chain(config.flock.iter().flat_map(|e| e.hooks.iter().flatten()))
        .map(|r| r.name().to_string())
        .collect();

    for name in &all_refs {
        if !config.service_hooks.contains_key(name.as_str()) {
            tracing::warn!(hook = %name, "Referenced hook not defined in serviceHooks");
        }
    }
}
