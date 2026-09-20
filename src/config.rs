//! Exceptions, each with a reason — the unit-lint pattern.
//!
//! An exception that no longer matches anything turns the run red. A list
//! that ages silently is worse than no list.

use serde::Deserialize;

#[derive(Debug, Deserialize, Default)]
pub struct Config {
    #[serde(default, rename = "exception")]
    pub exceptions: Vec<Exception>,
}

#[derive(Debug, Deserialize)]
pub struct Exception {
    pub secret: String,
    pub source: String,
    /// Mandatory. An exception without a reason is an omission.
    pub reason: String,
}

impl Config {
    pub fn excepted(&self, secret: &str, source: &str) -> bool {
        self.exceptions
            .iter()
            .any(|e| e.secret == secret && e.source == source)
    }

    /// Exceptions that matched nothing in this run.
    pub fn unused(&self, hits: &[(String, String)]) -> Vec<String> {
        self.exceptions
            .iter()
            .filter(|e| {
                !hits
                    .iter()
                    .any(|(s, src)| *s == e.secret && *src == e.source)
            })
            .map(|e| format!("{}/{}", e.secret, e.source))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_exception_matches_secret_and_source() {
        let c: Config = toml::from_str(
            r#"
            [[exception]]
            secret = "leakwatch-canary"
            source = "journal"
            reason = "die eigene Positivkontrolle"
            "#,
        )
        .unwrap();
        assert!(c.excepted("leakwatch-canary", "journal"));
        assert!(!c.excepted("leakwatch-canary", "loki"));
        assert!(!c.excepted("radarr-apikey", "journal"));
    }

    #[test]
    fn an_exception_without_a_reason_is_refused() {
        let r: Result<Config, _> = toml::from_str(
            r#"
            [[exception]]
            secret = "x"
            source = "journal"
            "#,
        );
        assert!(r.is_err(), "an exception without a reason was accepted");
    }

    #[test]
    fn unused_exceptions_are_reported() {
        let c: Config = toml::from_str(
            r#"
            [[exception]]
            secret = "gone"
            source = "journal"
            reason = "trifft nichts mehr"
            "#,
        )
        .unwrap();
        // After a run with no hit on `gone`:
        assert_eq!(c.unused(&[]), vec!["gone/journal".to_string()]);
    }
}
