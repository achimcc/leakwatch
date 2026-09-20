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

    /// Canary hits never become findings — `main` filters them before they can —
    /// so an exception naming the canary could never match, and an exception that
    /// matches nothing fails the run. Catching it here points at the real cause
    /// instead of at a stale-exception message.
    pub fn validate(&self) -> anyhow::Result<()> {
        if let Some(e) = self
            .exceptions
            .iter()
            .find(|e| e.secret == crate::canary::CANARY_NAME)
        {
            anyhow::bail!(
                "exception for {} ({}): canary hits are filtered before they become findings, \
                 so this exception can never match and would fail every run",
                e.secret,
                e.source
            );
        }
        Ok(())
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
            secret = "grafana-anon-token"
            source = "loki"
            reason = "the token is intentionally public on the read-only dashboard"
            "#,
        )
        .unwrap();
        assert!(c.excepted("grafana-anon-token", "loki"));
        assert!(!c.excepted("grafana-anon-token", "journal"));
        assert!(!c.excepted("radarr-apikey", "loki"));
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

    #[test]
    fn a_canary_exception_is_rejected() {
        let c: Config = toml::from_str(&format!(
            r#"
            [[exception]]
            secret = "{}"
            source = "journal"
            reason = "die eigene Positivkontrolle"
            "#,
            crate::canary::CANARY_NAME
        ))
        .unwrap();
        let err = c
            .validate()
            .expect_err("an exception naming the canary must be rejected");
        assert!(
            err.to_string().contains(crate::canary::CANARY_NAME),
            "error does not name the canary: {err}"
        );
    }

    #[test]
    fn a_config_without_a_canary_exception_validates() {
        let c: Config = toml::from_str(
            r#"
            [[exception]]
            secret = "grafana-anon-token"
            source = "loki"
            reason = "the token is intentionally public on the read-only dashboard"
            "#,
        )
        .unwrap();
        assert!(c.validate().is_ok());
    }
}
