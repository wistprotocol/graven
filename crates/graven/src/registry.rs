use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct LogEntry {
    pub log_id: String,
    pub anchor: String,
    pub base: String,
    pub tier1: bool,
    /// WIST-3 §5: further sources for the Log's static files, each tried
    /// when one does not hold a file.
    #[serde(default)]
    pub mirrors: Vec<String>,
    /// WIST-3 §5: the Witnesses this Consumer trusts, as the
    /// verifier-key strings they are configured in. Never read from the
    /// Log.
    #[serde(default)]
    pub witnesses: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Registry {
    pub logs: Vec<LogEntry>,
}

fn registry_path(dir: &Path) -> PathBuf {
    dir.join("logs.json")
}

pub fn load(dir: &Path) -> Result<Registry> {
    let path = registry_path(dir);
    if !path.exists() {
        return Ok(Registry::default());
    }
    let bytes = std::fs::read(&path)?;
    wist_core::json::validate(&bytes)?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub fn save(dir: &Path, reg: &Registry) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(registry_path(dir), serde_json::to_vec_pretty(reg)?)?;
    Ok(())
}

/// The registry file's octets as they stand, `None` where no log has been
/// registered yet, so a run that must leave no registration behind can
/// put the file back exactly — its absence included.
pub fn held(dir: &Path) -> Option<Vec<u8>> {
    std::fs::read(registry_path(dir)).ok()
}

pub fn restore(dir: &Path, held: Option<Vec<u8>>) -> Result<()> {
    let path = registry_path(dir);
    match held {
        Some(bytes) => std::fs::write(&path, bytes)?,
        None => match std::fs::remove_file(&path) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error.into()),
            _ => {}
        },
    }
    Ok(())
}

pub fn sanitize(log_id: &str) -> String {
    log_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

pub fn log_dir(dir: &Path, log_id: &str) -> PathBuf {
    dir.join("logs").join(sanitize(log_id))
}

pub fn find_collision<'a>(logs: &'a [LogEntry], log_id: &str) -> Option<&'a LogEntry> {
    let target = sanitize(log_id);
    logs.iter()
        .find(|e| e.log_id != log_id && sanitize(&e.log_id) == target)
}

pub fn validate_log_id(log_id: &str) -> Result<()> {
    let sanitized = sanitize(log_id);
    if sanitized.is_empty() || sanitized == "." || sanitized == ".." {
        return Err(Error::Verify(format!(
            "log_id {log_id:?} is not safe to use as a directory name (sanitizes to {sanitized:?})"
        )));
    }
    Ok(())
}

pub fn is_unmigrated_legacy_layout(dir: &Path) -> bool {
    !registry_path(dir).exists()
        && dir.join("index.sqlite").exists()
        && dir.join("sync.json").exists()
}

pub fn check_not_legacy(dir: &Path) -> Result<()> {
    if is_unmigrated_legacy_layout(dir) {
        return Err(Error::Verify(format!(
            "{} is a pre-registry graven directory (top-level index.sqlite/sync.json, no logs.json); run `graven sync --anchor <A> --log <URL> --dir {}` once to migrate to the per-log layout",
            dir.display(),
            dir.display()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_on_missing_file_returns_empty_registry() {
        let dir = tempfile::tempdir().unwrap();
        let reg = load(dir.path()).unwrap();
        assert!(reg.logs.is_empty());
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let reg = Registry {
            logs: vec![LogEntry {
                log_id: "a".into(),
                anchor: "anchor.json".into(),
                base: "https://log.example".into(),
                tier1: true,
                mirrors: Vec::new(),
                witnesses: Vec::new(),
            }],
        };
        save(dir.path(), &reg).unwrap();
        let loaded = load(dir.path()).unwrap();
        assert_eq!(loaded.logs, reg.logs);
    }

    #[test]
    fn sanitize_replaces_disallowed_chars() {
        assert_eq!(sanitize("http://127.0.0.1:9/x"), "http---127.0.0.1-9-x");
        assert_eq!(sanitize("graven-test-log"), "graven-test-log");
        assert_eq!(sanitize("a_b.c-d"), "a_b.c-d");
    }

    #[test]
    fn log_dir_joins_logs_and_sanitized_id() {
        let dir = Path::new("/tmp/graven-store");
        assert_eq!(log_dir(dir, "a b"), dir.join("logs/a-b"));
    }

    #[test]
    fn is_unmigrated_legacy_layout_requires_both_files_and_no_registry() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!is_unmigrated_legacy_layout(dir.path()));

        std::fs::write(dir.path().join("index.sqlite"), b"").unwrap();
        assert!(!is_unmigrated_legacy_layout(dir.path()));

        std::fs::write(dir.path().join("sync.json"), b"{}").unwrap();
        assert!(is_unmigrated_legacy_layout(dir.path()));

        save(dir.path(), &Registry::default()).unwrap();
        assert!(!is_unmigrated_legacy_layout(dir.path()));
    }

    #[test]
    fn validate_log_id_rejects_ids_that_sanitize_to_dot_dot_or_empty() {
        assert!(validate_log_id("..").is_err());
        assert!(validate_log_id(".").is_err());
        assert!(validate_log_id("").is_err());
        assert!(validate_log_id("graven-test-log").is_ok());
        assert!(validate_log_id("...").is_ok());
    }

    #[test]
    fn validate_log_id_error_names_the_offending_log_id() {
        let err = validate_log_id("..").unwrap_err();
        assert!(err.to_string().contains(".."), "error was: {err}");
    }

    fn entry(log_id: &str) -> LogEntry {
        LogEntry {
            log_id: log_id.into(),
            anchor: "a".into(),
            base: "b".into(),
            tier1: false,
            mirrors: Vec::new(),
            witnesses: Vec::new(),
        }
    }

    #[test]
    fn find_collision_detects_ids_that_sanitize_identically() {
        let logs = vec![entry("host:9")];
        let hit = find_collision(&logs, "host-9");
        assert_eq!(hit.map(|e| e.log_id.as_str()), Some("host:9"));
    }

    #[test]
    fn find_collision_ignores_the_same_log_id() {
        let logs = vec![entry("host-9")];
        assert!(find_collision(&logs, "host-9").is_none());
    }

    #[test]
    fn find_collision_ignores_distinct_non_colliding_ids() {
        let logs = vec![entry("log-one")];
        assert!(find_collision(&logs, "log-two").is_none());
    }
}
