//! Where the values come from. Two ways in, one shape out.
//!
//! On a host the secrets already lie in /run/secrets in plaintext — every
//! service reads them from there. An HMAC index on the same machine would
//! protect against nothing and would cost a tokenizer that has to guess.

use anyhow::{Context, Result, bail};
use std::path::PathBuf;
use zeroize::Zeroize;

pub trait Secrets {
    fn load(&self) -> Result<Vec<(String, String)>>;
}

/// sops-nix on the machine: /run/secrets and /run/secrets/rendered.
pub struct RuntimeSecrets {
    pub roots: Vec<PathBuf>,
}

/// What [`RuntimeSecrets::load_detailed`] saw.
pub struct Loaded {
    pub values: Vec<(String, String)>,
    /// Regular files (or whole roots) that exist but could not be read —
    /// a non-root caller on the host sees `/run/secrets/rendered` like that.
    pub unreadable: usize,
}

impl RuntimeSecrets {
    fn read_roots(&self, prefix_rendered: bool) -> Loaded {
        let mut out = Vec::new();
        let mut unreadable = 0;
        for root in &self.roots {
            let prefix = if prefix_rendered && root.file_name().is_some_and(|f| f == "rendered") {
                "rendered/"
            } else {
                ""
            };
            // Recursive since 0.3.2: sops-nix writes a secret `a/b` as
            // `<root>/a/b`; a subdirectory skipped silently was a gap the
            // closing line could not show. The `rendered` root is a child
            // of `/run/secrets` and is read as its own root, not twice.
            let mut stack = vec![root.clone()];
            while let Some(dir) = stack.pop() {
                let entries = match std::fs::read_dir(&dir) {
                    Ok(e) => e,
                    Err(_) => {
                        if dir.exists() {
                            unreadable += 1;
                        }
                        continue;
                    }
                };
                for entry in entries {
                    let Ok(entry) = entry else {
                        unreadable += 1;
                        continue;
                    };
                    let kind = entry.file_type();
                    if kind.as_ref().is_ok_and(|t| t.is_dir()) {
                        if self.roots.iter().any(|r| *r == entry.path()) {
                            continue;
                        }
                        stack.push(entry.path());
                        continue;
                    }
                    if !kind.is_ok_and(|t| t.is_file()) {
                        continue;
                    }
                    let Ok(mut value) = std::fs::read_to_string(entry.path()) else {
                        unreadable += 1;
                        continue;
                    };
                    let rel = entry
                        .path()
                        .strip_prefix(root)
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap_or_else(|_| entry.file_name().to_string_lossy().into_owned());
                    let name = format!("{prefix}{rel}");
                    // In place, not a trimmed copy: every copy is one more
                    // buffer that outlives its use. `Scanner::new` wipes it.
                    if value.ends_with('\n') {
                        value.pop();
                    }
                    out.push((name, value));
                }
            }
        }
        Loaded {
            values: out,
            unreadable,
        }
    }

    /// Like `load`, but says what it could not read, and names a value from
    /// a `rendered` root with the prefix `rendered/` (a template, which
    /// contains secrets rather than being one).
    pub fn load_detailed(&self) -> Result<Loaded> {
        let loaded = self.read_roots(true);
        if loaded.values.is_empty() && loaded.unreadable == 0 {
            bail!(
                "no secrets found under {:?} — without patterns a run says nothing",
                self.roots
            );
        }
        Ok(loaded)
    }
}

impl Secrets for RuntimeSecrets {
    fn load(&self) -> Result<Vec<(String, String)>> {
        let out = self.read_roots(false).values;
        if out.is_empty() {
            bail!(
                "no secrets found under {:?} — without patterns a run says nothing",
                self.roots
            );
        }
        Ok(out)
    }
}

/// The secrets repository on the workstation, read through `sops --decrypt`.
pub struct SopsSecrets {
    pub repo: PathBuf,
}

impl Secrets for SopsSecrets {
    fn load(&self) -> Result<Vec<(String, String)>> {
        let mut out = Vec::new();
        for entry in walk_yaml(&self.repo.join("secrets"))? {
            let mut output = std::process::Command::new("sops")
                .arg("--decrypt")
                .arg(&entry)
                .output()
                .with_context(|| format!("running sops on {entry:?}"))?;
            if !output.status.success() {
                bail!("sops --decrypt failed for {entry:?}");
            }
            let parsed = parse_sops_yaml(&String::from_utf8_lossy(&output.stdout));
            output.stdout.zeroize();
            out.extend(parsed?);
        }
        if out.is_empty() {
            bail!("no secrets decrypted from {:?}", self.repo);
        }
        Ok(out)
    }
}

fn walk_yaml(dir: &std::path::Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {dir:?}"))? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk_yaml(&path)?);
        } else if path.extension().is_some_and(|e| e == "yaml") {
            out.push(path);
        }
    }
    Ok(out)
}

/// Parse YAML scalars from a decrypted sops file. Block scalars, folded scalars,
/// quoting, escapes and nesting are all handled by the YAML parser.
/// For nested mappings, keys are joined with `.` (e.g. `outer.inner`).
/// Non-scalar leaves (empty mappings, nulls) are skipped.
/// The top-level `sops` key is skipped structurally.
pub fn parse_sops_yaml(text: &str) -> Result<Vec<(String, String)>> {
    let value: serde_norway::Value = serde_norway::from_str(text)?;

    let mut out = Vec::new();
    collect_scalars(&value, String::new(), &mut out);
    Ok(out)
}

/// Recursively collect scalar leaves from a YAML value.
/// For mappings, join keys with `.`. For sequences, skip (not used in sops files).
/// The top-level `sops` key is skipped.
fn collect_scalars(value: &serde_norway::Value, prefix: String, out: &mut Vec<(String, String)>) {
    match value {
        serde_norway::Value::Mapping(map) => {
            for (k, v) in map.iter() {
                let key_str = match k {
                    serde_norway::Value::String(s) => s.clone(),
                    _ => continue,
                };

                // Skip the sops key structurally
                if key_str == "sops" {
                    continue;
                }

                let new_prefix = if prefix.is_empty() {
                    key_str
                } else {
                    format!("{}.{}", prefix, key_str)
                };

                collect_scalars(v, new_prefix, out);
            }
        }
        serde_norway::Value::String(s) => {
            if !prefix.is_empty() {
                out.push((prefix, s.clone()));
            }
        }
        serde_norway::Value::Number(n) => {
            if !prefix.is_empty() {
                out.push((prefix, n.to_string()));
            }
        }
        serde_norway::Value::Bool(b) => {
            if !prefix.is_empty() {
                out.push((prefix, b.to_string()));
            }
        }
        serde_norway::Value::Null
        | serde_norway::Value::Sequence(_)
        | serde_norway::Value::Tagged(_) => {
            // Skip nulls, sequences, and tagged values
        }
    }
}

/// The sentence a run prints about its own coverage. A run that silently
/// searches for fewer values than exist is the kind of promise Mealie and
/// Ghostfolio made.
pub fn skipped_short(all: usize, used: usize) -> String {
    format!(
        "{} of {all} secrets are shorter than the minimum length and are not searched",
        all.saturating_sub(used)
    )
}

/// How many loaded values span more than one line. Such a value cannot
/// match a single scanned line as it is; it is found JSON-escaped (one log
/// line) and through those of its lines that look like key material (see
/// `variants::lines`) — a real limit, and one a run has to state rather than
/// leave silent. Taking every line as its own pattern is not the answer:
/// `-----BEGIN PRIVATE KEY-----` would then match every PEM.
pub fn multiline_note(values: &[(String, String)]) -> Option<String> {
    let n = values.iter().filter(|(_, v)| v.contains('\n')).count();
    (n > 0).then(|| {
        format!(
            "{n} patterns span multiple lines and are found only JSON-escaped or by their key-shaped lines"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review 2026-10-23: sops-nix writes a secret `a/b` as `/run/secrets/a/b`;
    /// a subdirectory is read, named with the slash — never skipped silently.
    #[test]
    fn load_detailed_reads_subdirectories() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("nested/deep")).unwrap();
        std::fs::write(
            dir.path().join("nested/deep/key"),
            "nested-value-ZYXWVU987654",
        )
        .unwrap();
        std::fs::write(dir.path().join("plain"), "plain-value-0123456789").unwrap();
        let s = RuntimeSecrets {
            roots: vec![dir.path().to_path_buf()],
        };
        let got = s.load_detailed().unwrap();
        let mut names: Vec<&str> = got.values.iter().map(|(n, _)| n.as_str()).collect();
        names.sort();
        assert_eq!(names, vec!["nested/deep/key", "plain"]);
    }

    #[test]
    fn load_detailed_counts_unreadable_and_prefixes_rendered() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let rendered = dir.path().join("rendered");
        std::fs::create_dir(&rendered).unwrap();
        std::fs::write(dir.path().join("plain-key"), "abc123def456\n").unwrap();
        std::fs::write(rendered.join("service-env"), "KEY=abc123def456\n").unwrap();
        let locked = dir.path().join("locked-key");
        std::fs::write(&locked, "zzz999yyy888").unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read_to_string(&locked).is_ok() {
            return; // root reads everything; the count cannot be provoked
        }
        let s = RuntimeSecrets {
            roots: vec![dir.path().to_path_buf(), rendered.clone()],
        };
        let got = s.load_detailed().unwrap();
        let mut names: Vec<&str> = got.values.iter().map(|(n, _)| n.as_str()).collect();
        names.sort();
        assert_eq!(names, vec!["plain-key", "rendered/service-env"]);
        assert_eq!(got.unreadable, 1);
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o600)).unwrap();
        // `load` is untouched: no prefix, nothing counted.
        let plain = s.load().unwrap();
        assert!(plain.iter().any(|(n, _)| n == "service-env"));
    }

    #[test]
    fn runtime_reads_every_file_in_a_root() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("radarr-apikey"), "abc123def456").unwrap();
        std::fs::write(dir.path().join("sonarr-apikey"), "zzz999yyy888\n").unwrap();
        let s = RuntimeSecrets {
            roots: vec![dir.path().to_path_buf()],
        };
        let mut got = s.load().unwrap();
        got.sort();
        assert_eq!(
            got,
            vec![
                ("radarr-apikey".to_string(), "abc123def456".to_string()),
                ("sonarr-apikey".to_string(), "zzz999yyy888".to_string()),
            ]
        );
    }

    #[test]
    fn runtime_trims_only_the_trailing_newline() {
        // A password may contain spaces inside; only the trailing newline
        // that sops-nix appends is removed.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("pw"), "  spaces inside  \n").unwrap();
        let s = RuntimeSecrets {
            roots: vec![dir.path().to_path_buf()],
        };
        assert_eq!(s.load().unwrap()[0].1, "  spaces inside  ");
    }

    #[test]
    fn runtime_skips_directories_and_unreadable_entries() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("rendered")).unwrap();
        std::fs::write(dir.path().join("ok"), "abc123def456").unwrap();
        let s = RuntimeSecrets {
            roots: vec![dir.path().to_path_buf()],
        };
        assert_eq!(s.load().unwrap().len(), 1);
    }

    #[test]
    fn runtime_reports_an_empty_root_as_an_error() {
        // An empty /run/secrets means: the run has NO patterns. That is a
        // tool error, not a clean result.
        let dir = tempfile::tempdir().unwrap();
        let s = RuntimeSecrets {
            roots: vec![dir.path().to_path_buf()],
        };
        assert!(s.load().is_err());
    }

    #[test]
    fn skipped_short_names_the_gap() {
        let msg = skipped_short(200, 186);
        assert!(msg.contains("14"), "does not name the count: {msg}");
    }

    #[test]
    fn sops_parses_a_decrypted_yaml_mapping() {
        let yaml = "radarr-apikey: abc123def456\nsonarr-apikey: zzz999yyy888\n";
        let got = parse_sops_yaml(yaml).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(
            got[0],
            ("radarr-apikey".to_string(), "abc123def456".to_string())
        );
    }

    #[test]
    fn sops_ignores_the_sops_metadata_block() {
        // sops 3.13.3 does not emit this block on --decrypt; the guard is
        // deliberate so a future version or a hand-written file cannot smuggle
        // key material in as a secret.
        let yaml = "key: abc123def456\nsops:\n  age:\n    - recipient: xyz\n";
        let got = parse_sops_yaml(yaml).unwrap();
        assert_eq!(got.len(), 1, "sops metadata leaked in: {got:?}");
        assert_eq!(got[0].0, "key");
    }

    #[test]
    fn sops_keeps_a_quoted_value_with_a_colon() {
        let yaml = "url: \"https://example.org/a:b\"\n";
        let got = parse_sops_yaml(yaml).unwrap();
        assert_eq!(got[0].1, "https://example.org/a:b");
    }

    #[test]
    fn sops_reads_a_block_scalar_whole() {
        let yaml = "pem: |\n  -----BEGIN KEY-----\n  abcdefghijklmnop\n  -----END KEY-----\n";
        let got = parse_sops_yaml(yaml).unwrap();
        assert_eq!(got.len(), 1);
        assert!(
            got[0].1.contains("abcdefghijklmnop"),
            "body lost: {:?}",
            got[0].1
        );
        assert!(got[0].1.contains("BEGIN KEY"), "first body line lost");
        assert_ne!(
            got[0].1, "|",
            "the old line parser returned the indicator itself"
        );
    }

    #[test]
    fn sops_reads_a_nested_mapping() {
        let yaml = "outer:\n  inner: abc123def456\n";
        let got = parse_sops_yaml(yaml).unwrap();
        assert_eq!(
            got,
            vec![("outer.inner".to_string(), "abc123def456".to_string())]
        );
    }

    #[test]
    fn sops_skips_the_sops_key_structurally() {
        let yaml = "real: abc123def456\nsops:\n  age:\n    - recipient: xyz789\n";
        let got = parse_sops_yaml(yaml).unwrap();
        assert_eq!(got.len(), 1, "sops metadata leaked in: {got:?}");
        assert_eq!(got[0].0, "real");
    }

    #[test]
    fn multiline_note_names_the_count() {
        let values = vec![
            ("single".to_string(), "one line".to_string()),
            ("multi".to_string(), "line one\nline two".to_string()),
        ];
        let msg = multiline_note(&values);
        assert!(msg.is_some(), "no note returned");
        let msg = msg.unwrap();
        assert!(msg.contains("1"), "does not name the count: {msg}");
    }

    #[test]
    fn multiline_note_returns_none_for_all_single_line() {
        let values = vec![("key1".to_string(), "value1".to_string())];
        assert!(multiline_note(&values).is_none());
    }
}
