//! Alertmanager's alerts — labels and annotations of every alert it holds
//! (firing, silenced, inhibited). An annotation renders a value from the
//! alert's series or a template; a secret that lands there goes out by mail
//! and ntfy, and neither journal nor Loki sees it (audit 4, B222).
//!
//! WHAT IT DOES NOT SEE: notifications already sent and resolved alerts —
//! Alertmanager keeps no history of payloads. The ntfy source covers what
//! went out as a push.
//!
//! One alert is one line: `<fingerprint>\t<k>=<v> …`, labels first, then
//! annotations, CR/LF folded to spaces. The location of a finding is the
//! fingerprint, never content. The Watchdog alert is always firing, so a
//! healthy Alertmanager is never a silent source.

use super::loki::shell_quote;
use super::{Source, spawn};
use anyhow::{Context, Result};
use std::io::{BufRead, Read};

pub struct Alertmanager {
    pub base: String,
    pub via_ssh: Option<String>,
}

impl Alertmanager {
    pub fn command(&self) -> Vec<String> {
        let url = format!(
            "{}/api/v2/alerts?active=true&silenced=true&inhibited=true&unprocessed=true",
            self.base.trim_end_matches('/')
        );
        let curl = vec![
            "curl".to_string(),
            "-sSG".to_string(),
            "--fail".to_string(),
            "--max-time".to_string(),
            "60".to_string(),
            url,
        ];
        match &self.via_ssh {
            None => curl,
            Some(target) => vec![
                "ssh".to_string(),
                "-o".to_string(),
                "IdentitiesOnly=yes".to_string(),
                target.clone(),
                curl.iter()
                    .map(|a| shell_quote(a))
                    .collect::<Vec<_>>()
                    .join(" "),
            ],
        }
    }
}

fn fold(s: &str) -> String {
    s.replace(['\n', '\r', '\t'], " ")
}

/// The answer of `/api/v2/alerts` as lines, one per alert.
pub fn lines_of(body: &[u8]) -> Result<String> {
    let alerts: Vec<serde_json::Value> =
        serde_json::from_slice(body).context("alertmanager: the answer is not a JSON array")?;
    let mut out = String::new();
    for a in &alerts {
        let fp = a.get("fingerprint").and_then(|f| f.as_str()).unwrap_or("");
        out.push_str(&fold(fp));
        for key in ["labels", "annotations"] {
            if let Some(map) = a.get(key).and_then(|m| m.as_object()) {
                for (k, v) in map {
                    let v = v
                        .as_str()
                        .map(str::to_string)
                        .unwrap_or_else(|| v.to_string());
                    out.push('\t');
                    out.push_str(&fold(k));
                    out.push('=');
                    out.push_str(&fold(&v));
                }
            }
        }
        out.push('\n');
    }
    Ok(out)
}

/// The fingerprint at the start of a line — hex only, at most 32 characters.
pub fn fingerprint_of(line: &str) -> Option<&str> {
    let fp = line.split('\t').next()?;
    (!fp.is_empty() && fp.len() <= 32 && fp.bytes().all(|b| b.is_ascii_hexdigit())).then_some(fp)
}

impl Source for Alertmanager {
    fn name(&self) -> &str {
        "alertmanager"
    }
    fn open(&self) -> Result<Box<dyn BufRead>> {
        let mut body = Vec::new();
        spawn(&self.command())?
            .read_to_end(&mut body)
            .context("alertmanager: reading the answer")?;
        Ok(Box::new(std::io::Cursor::new(
            lines_of(&body)?.into_bytes(),
        )))
    }
    fn locate(&self, line: &str) -> (String, String) {
        match fingerprint_of(line) {
            Some(fp) => ("alertmanager".to_string(), fp.to_string()),
            None => ("alertmanager".to_string(), self.base.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ANSWER: &str = r#"[
      {"fingerprint":"a1b2c3d4e5f60718","labels":{"alertname":"Watchdog","severity":"none"},
       "annotations":{"summary":"always\nfiring"},"status":{"state":"active"}},
      {"fingerprint":"0f0f0f0f0f0f0f0f","labels":{"alertname":"X","n":"3"},
       "annotations":{"description":"see https://h/x?token=SECRETVALUE1234"}}
    ]"#;

    #[test]
    fn every_alert_is_one_line_with_labels_and_annotations() {
        let text = lines_of(ANSWER.as_bytes()).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("a1b2c3d4e5f60718\t"));
        assert!(lines[0].contains("summary=always firing"), "{}", lines[0]);
        assert!(lines[1].contains("token=SECRETVALUE1234"));
    }

    #[test]
    fn a_non_array_answer_is_an_error_not_a_quiet_source() {
        assert!(lines_of(b"{\"status\":\"error\"}").is_err());
        assert!(lines_of(b"<html>").is_err());
    }

    #[test]
    fn a_location_carries_only_the_hex_fingerprint() {
        let a = Alertmanager {
            base: "http://am:9093".into(),
            via_ssh: None,
        };
        assert_eq!(a.locate("a1b2c3\tk=v").1, "a1b2c3");
        assert_eq!(a.locate("not-hex!\tk=v").1, "http://am:9093");
    }

    #[test]
    fn the_url_asks_for_silenced_and_inhibited_alerts_too() {
        let a = Alertmanager {
            base: "http://am:9093/".into(),
            via_ssh: Some("r@h".into()),
        };
        let c = a.command();
        assert!(c[4].contains("'http://am:9093/api/v2/alerts?active=true&silenced=true&inhibited=true&unprocessed=true'"), "{}", c[4]);
    }
}
