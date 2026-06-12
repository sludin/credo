use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;

pub fn write_pid(path: &Path) -> Result<()> {
    std::fs::write(path, format!("{}\n", std::process::id()))
        .with_context(|| format!("failed to write PID file {}", path.display()))
}

pub fn read_pid(path: &Path) -> Result<u32> {
    std::fs::read_to_string(path)
        .with_context(|| format!("failed to read PID file {}", path.display()))?
        .trim()
        .parse::<u32>()
        .with_context(|| format!("invalid PID in {}", path.display()))
}

pub fn remove_pid(path: &Path) {
    let _ = std::fs::remove_file(path);
}

pub fn is_running(pid: u32) -> bool {
    kill(Pid::from_raw(pid as i32), None).is_ok()
}

/// RAII guard: writes the current process PID on creation, removes the file on drop.
pub struct PidGuard {
    path: PathBuf,
}

impl PidGuard {
    pub fn new(path: PathBuf) -> Result<Self> {
        write_pid(&path)?;
        Ok(PidGuard { path })
    }
}

impl Drop for PidGuard {
    fn drop(&mut self) {
        remove_pid(&self.path);
    }
}

/// Send SIGTERM to the process identified by `pid_path` and wait up to `timeout_secs` for it
/// to exit. Removes a stale PID file if the recorded process is no longer alive.
pub fn stop_service(pid_path: &Path, timeout_secs: u64) -> Result<()> {
    if !pid_path.exists() {
        bail!(
            "service is not running (no PID file at {})",
            pid_path.display()
        );
    }

    let pid = read_pid(pid_path)?;

    if !is_running(pid) {
        remove_pid(pid_path);
        bail!(
            "service is not running (stale PID file removed; PID {} was not alive)",
            pid
        );
    }

    kill(Pid::from_raw(pid as i32), Signal::SIGTERM)
        .with_context(|| format!("failed to send SIGTERM to PID {}", pid))?;

    let deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    while std::time::Instant::now() < deadline {
        if !is_running(pid) {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    bail!("service (PID {}) did not stop within {}s", pid, timeout_secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn pid_guard_writes_and_removes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.pid");
        {
            let _guard = PidGuard::new(path.clone()).unwrap();
            let pid = read_pid(&path).unwrap();
            assert_eq!(pid, std::process::id());
            assert!(is_running(pid));
        }
        assert!(!path.exists(), "PID file should be removed on drop");
    }

    #[test]
    fn stale_pid_detected() {
        // Spawn a short-lived child, reap it, then verify is_running returns false.
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();
        assert!(!is_running(pid));
    }

    #[test]
    fn stop_nonexistent_service_errors() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("missing.pid");
        let result = stop_service(&path, 5);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not running"));
    }
}
