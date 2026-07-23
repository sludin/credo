use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

/// How a service's rotating log file grows and prunes old segments.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RotationConfig {
    pub size_mb: u64,
    pub keep_files: usize,
}

impl Default for RotationConfig {
    fn default() -> Self {
        RotationConfig {
            size_mb: 100,
            keep_files: 12,
        }
    }
}

/// Config-driven logging sink: an app-owned rotating file plus an in-memory
/// broadcast of each completed line, in addition to (optionally) stdout.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoggingConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_log_dir")]
    pub dir: String,
    #[serde(default)]
    pub rotate_on: RotationConfig,
    #[serde(default = "default_also_stdout")]
    pub also_stdout: bool,
}

fn default_log_dir() -> String {
    "logs".to_string()
}

fn default_also_stdout() -> bool {
    true
}

impl Default for LoggingConfig {
    fn default() -> Self {
        LoggingConfig {
            enabled: false,
            dir: default_log_dir(),
            rotate_on: RotationConfig::default(),
            also_stdout: true,
        }
    }
}

struct RotatingFileState {
    dir: PathBuf,
    basename: String,
    max_bytes: u64,
    keep_files: usize,
    file: File,
    current_bytes: u64,
    pending: Vec<u8>,
}

impl RotatingFileState {
    fn open_current(dir: &Path, basename: &str) -> io::Result<(File, u64)> {
        fs::create_dir_all(dir)?;
        let path = dir.join(format!("{basename}.log"));
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let current_bytes = file.metadata()?.len();
        Ok((file, current_bytes))
    }

    fn rotate(&mut self) -> io::Result<()> {
        for i in (1..self.keep_files).rev() {
            let from = self.dir.join(format!("{}.{}.log", self.basename, i));
            let to = self.dir.join(format!("{}.{}.log", self.basename, i + 1));
            if from.exists() {
                fs::rename(&from, &to)?;
            }
        }
        let current = self.dir.join(format!("{}.log", self.basename));
        let first_rotated = self.dir.join(format!("{}.1.log", self.basename));
        fs::rename(&current, &first_rotated)?;
        let (file, _) = Self::open_current(&self.dir, &self.basename)?;
        self.file = file;
        self.current_bytes = 0;
        Ok(())
    }
}

/// A `std::io::Write` sink that appends to a size-rotated file and
/// broadcasts every completed line to any live subscribers. Cloning shares
/// the same underlying file handle and broadcast channel.
#[derive(Clone)]
pub struct RotatingFileWriter {
    state: Arc<Mutex<RotatingFileState>>,
    tx: broadcast::Sender<String>,
}

const BROADCAST_CAPACITY: usize = 2048;

impl RotatingFileWriter {
    pub fn new(dir: &Path, basename: &str, rotate_on: &RotationConfig) -> io::Result<Self> {
        let (file, current_bytes) = RotatingFileState::open_current(dir, basename)?;
        let state = RotatingFileState {
            dir: dir.to_path_buf(),
            basename: basename.to_string(),
            max_bytes: rotate_on.size_mb.max(1) * 1024 * 1024,
            keep_files: rotate_on.keep_files.max(1),
            file,
            current_bytes,
            pending: Vec::new(),
        };
        let (tx, _rx) = broadcast::channel(BROADCAST_CAPACITY);
        Ok(RotatingFileWriter {
            state: Arc::new(Mutex::new(state)),
            tx,
        })
    }

    /// Subscribe to a live feed of completed lines written from this point on.
    pub fn subscribe(&self) -> broadcast::Receiver<String> {
        self.tx.subscribe()
    }
}

impl Write for RotatingFileWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut state = self
            .state
            .lock()
            .expect("rotating file writer state poisoned");
        if state.current_bytes > 0 && state.current_bytes + buf.len() as u64 > state.max_bytes {
            state.rotate()?;
        }
        state.file.write_all(buf)?;
        state.current_bytes += buf.len() as u64;
        state.pending.extend_from_slice(buf);
        while let Some(pos) = state.pending.iter().position(|&b| b == b'\n') {
            let line_bytes: Vec<u8> = state.pending.drain(..=pos).collect();
            if let Ok(text) = std::str::from_utf8(&line_bytes) {
                let _ = self
                    .tx
                    .send(text.trim_end_matches(['\n', '\r']).to_string());
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.state
            .lock()
            .expect("rotating file writer state poisoned")
            .file
            .flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn rotate_on(size_mb: u64, keep_files: usize) -> RotationConfig {
        RotationConfig {
            size_mb,
            keep_files,
        }
    }

    #[test]
    fn write_appends_to_current_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut writer =
            RotatingFileWriter::new(dir.path(), "svc", &rotate_on(100, 12)).expect("new writer");
        writer.write_all(b"line one\n").expect("write 1");
        writer.write_all(b"line two\n").expect("write 2");
        writer.flush().expect("flush");

        let contents = fs::read_to_string(dir.path().join("svc.log")).expect("read log file");
        assert_eq!(contents, "line one\nline two\n");
    }

    #[test]
    fn rotation_prunes_beyond_keep_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        // 1 MB threshold, keep 2 backups. Each chunk below is ~600KB so two
        // chunks together always cross the threshold, forcing rotation on
        // every write after the first.
        let mut writer =
            RotatingFileWriter::new(dir.path(), "svc", &rotate_on(1, 2)).expect("new writer");

        let chunk = |byte: u8| {
            let mut v = vec![byte; 600_000];
            v.push(b'\n');
            v
        };
        writer.write_all(&chunk(b'A')).expect("write A"); // current = A
        writer.write_all(&chunk(b'B')).expect("write B"); // rotate: .1=A, current=B
        writer.write_all(&chunk(b'C')).expect("write C"); // rotate: .2=A, .1=B, current=C
        writer.write_all(&chunk(b'D')).expect("write D"); // rotate: .2=B (A pruned), .1=C, current=D
        writer.flush().expect("flush");

        let current = fs::read(dir.path().join("svc.log")).expect("read current");
        let backup1 = fs::read(dir.path().join("svc.1.log")).expect("read .1");
        let backup2 = fs::read(dir.path().join("svc.2.log")).expect("read .2");
        assert_eq!(current[0], b'D');
        assert_eq!(backup1[0], b'C');
        assert_eq!(backup2[0], b'B');
        assert!(
            !dir.path().join("svc.3.log").exists(),
            "must not keep more than keep_files backups"
        );
    }

    #[test]
    fn write_broadcasts_completed_lines_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut writer =
            RotatingFileWriter::new(dir.path(), "svc", &rotate_on(100, 12)).expect("new writer");
        let mut rx = writer.subscribe();

        // A write with no newline yet must not broadcast anything - this is
        // the case tracing's fmt layer can hit if it calls write() more
        // than once per event.
        writer.write_all(b"partial-").expect("write partial");
        assert!(matches!(
            rx.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));

        writer.write_all(b"rest\n").expect("write rest");
        let line = rx.try_recv().expect("expected one broadcast line");
        assert_eq!(line, "partial-rest");
        assert!(matches!(
            rx.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn logging_config_deserializes_with_defaults() {
        let config: LoggingConfig = serde_json::from_str(r#"{"enabled": true}"#).expect("parse");
        assert!(config.enabled);
        assert_eq!(config.dir, "logs");
        assert_eq!(config.rotate_on.size_mb, 100);
        assert_eq!(config.rotate_on.keep_files, 12);
        assert!(config.also_stdout);
    }
}
