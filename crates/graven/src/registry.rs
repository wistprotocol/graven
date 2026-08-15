use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct LogEntry {
    pub log_id: String,
    pub anchor: String,
    pub base: String,
    pub tier1: bool,
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
    Ok(serde_json::from_slice(&bytes)?)
}

pub fn save(dir: &Path, reg: &Registry) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(registry_path(dir), serde_json::to_vec_pretty(reg)?)?;
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

pub fn resolve_default_log(dir: &Path) -> Result<LogEntry> {
    check_not_legacy(dir)?;
    let reg = load(dir)?;
    let entry = reg.logs.into_iter().next().ok_or_else(|| {
        Error::Verify(format!(
            "no logs registered in {}; run `graven follow` first",
            dir.display()
        ))
    })?;
    validate_log_id(&entry.log_id)?;
    Ok(entry)
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

    #[test]
    fn resolve_default_log_returns_first_entry() {
        let dir = tempfile::tempdir().unwrap();
        let reg = Registry {
            logs: vec![
                LogEntry {
                    log_id: "a".into(),
                    anchor: "anchor-a".into(),
                    base: "https://a.example".into(),
                    tier1: false,
                },
                LogEntry {
                    log_id: "b".into(),
                    anchor: "anchor-b".into(),
                    base: "https://b.example".into(),
                    tier1: true,
                },
            ],
        };
        save(dir.path(), &reg).unwrap();
        let entry = resolve_default_log(dir.path()).unwrap();
        assert_eq!(entry.log_id, "a");
    }

    #[test]
    fn resolve_default_log_errors_when_no_logs_registered() {
        let dir = tempfile::tempdir().unwrap();
        let err = resolve_default_log(dir.path()).unwrap_err();
        assert!(
            err.to_string().contains("run `graven follow`"),
            "error was: {err}"
        );
    }

    #[test]
    fn resolve_default_log_rejects_a_hand_edited_unsafe_log_id() {
        let dir = tempfile::tempdir().unwrap();
        let reg = Registry {
            logs: vec![LogEntry {
                log_id: "..".into(),
                anchor: "anchor.json".into(),
                base: "https://log.example".into(),
                tier1: false,
            }],
        };
        save(dir.path(), &reg).unwrap();

        let err = resolve_default_log(dir.path()).unwrap_err();
        assert!(err.to_string().contains(".."), "error was: {err}");
    }
}
