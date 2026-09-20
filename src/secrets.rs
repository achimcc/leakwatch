//! Where the values come from. Two ways in, one shape out.
//!
//! On a host the secrets already lie in /run/secrets in plaintext — every
//! service reads them from there. An HMAC index on the same machine would
//! protect against nothing and would cost a tokenizer that has to guess.

use anyhow::{Context, Result, bail};
use std::path::PathBuf;

pub trait Secrets {
    fn load(&self) -> Result<Vec<(String, String)>>;
}

/// sops-nix on the machine: /run/secrets and /run/secrets/rendered.
pub struct RuntimeSecrets {
    pub roots: Vec<PathBuf>,
}

impl Secrets for RuntimeSecrets {
    fn load(&self) -> Result<Vec<(String, String)>> {
        let mut out = Vec::new();
        for root in &self.roots {
            let entries = match std::fs::read_dir(root) {
                Ok(e) => e,
                Err(_) => continue,
            };
            for entry in entries.flatten() {
                if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                    continue;
                }
                let Ok(value) = std::fs::read_to_string(entry.path()) else {
                    continue;
                };
                let name = entry.file_name().to_string_lossy().to_string();
                out.push((name, value.strip_suffix('\n').unwrap_or(&value).to_string()));
            }
        }
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
            let output = std::process::Command::new("sops")
                .arg("--decrypt")
                .arg(&entry)
                .output()
                .with_context(|| format!("running sops on {entry:?}"))?;
            if !output.status.success() {
                bail!("sops --decrypt failed for {entry:?}");
            }
            let text = String::from_utf8_lossy(&output.stdout);
            out.extend(parse_sops_yaml(&text)?);
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
    let value: serde_yaml::Value = serde_yaml::from_str(text)?;

    let mut out = Vec::new();
    collect_scalars(&value, String::new(), &mut out);
    Ok(out)
}

/// Recursively collect scalar leaves from a YAML value.
/// For mappings, join keys with `.`. For sequences, skip (not used in sops files).
/// The top-level `sops` key is skipped.
fn collect_scalars(value: &serde_yaml::Value, prefix: String, out: &mut Vec<(String, String)>) {
    match value {
        serde_yaml::Value::Mapping(map) => {
            for (k, v) in map.iter() {
                let key_str = match k {
                    serde_yaml::Value::String(s) => s.clone(),
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
        serde_yaml::Value::String(s) => {
            if !prefix.is_empty() {
                out.push((prefix, s.clone()));
            }
        }
        serde_yaml::Value::Number(n) => {
            if !prefix.is_empty() {
                out.push((prefix, n.to_string()));
            }
        }
        serde_yaml::Value::Bool(b) => {
            if !prefix.is_empty() {
                out.push((prefix, b.to_string()));
            }
        }
        serde_yaml::Value::Null | serde_yaml::Value::Sequence(_) | serde_yaml::Value::Tagged(_) => {
            // Skip nulls, sequences, and tagged values
        }
    }
}

/// The sentence a run prints about its own coverage. A run that silently
/// searches for fewer values than exist is the kind of promise Mealie and
/// Ghostfolio made.
pub fn skipped_short(all: usize, used: usize) -> String {
    format!(
        "{} von {all} Geheimnissen sind kürzer als die Mindestlänge und werden NICHT gesucht",
        all.saturating_sub(used)
    )
}

/// How many loaded values span more than one line. Such a value is only found
/// if it appears in the data in full — a real limit, and one a run has to
/// state rather than leave silent. Taking each line as its own pattern is not
/// the answer: `-----BEGIN PRIVATE KEY-----` would then match every PEM.
pub fn multiline_note(values: &[(String, String)]) -> Option<String> {
    let n = values.iter().filter(|(_, v)| v.contains('\n')).count();
    (n > 0).then(|| {
        format!("{n} Muster sind mehrzeilig und werden nur gefunden, wenn sie vollständig dastehen")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
        // Ein Passwort darf innen Leerzeichen haben; nur der abschliessende
        // Zeilenumbruch, den sops-nix anhaengt, faellt weg.
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
        // Ein leeres /run/secrets heisst: der Lauf hat KEINE Muster. Das ist
        // ein Werkzeugfehler, kein sauberes Ergebnis.
        let dir = tempfile::tempdir().unwrap();
        let s = RuntimeSecrets {
            roots: vec![dir.path().to_path_buf()],
        };
        assert!(s.load().is_err());
    }

    #[test]
    fn skipped_short_names_the_gap() {
        let msg = skipped_short(200, 186);
        assert!(msg.contains("14"), "nennt die Zahl nicht: {msg}");
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
        assert_eq!(got.len(), 1, "sops-Metadaten mitgelesen: {got:?}");
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
