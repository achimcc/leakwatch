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
    /// Opt out of the staleness check for a finding that is legitimate but
    /// INTERMITTENT.
    ///
    /// WHY THIS EXISTS: "an exception that matches nothing turns the run red"
    /// is there to stop a list from rotting. It assumes a finding either
    /// keeps happening or is gone for good. Real logs are not like that. A
    /// mail server writes the sender address when it sends mail and stays
    /// quiet otherwise; a client logs its own account name when it
    /// reconnects. Such an exception matches in one window and not in the
    /// next, and both available answers are wrong: keep it and the run goes
    /// red for a healthy system, drop it and an identifier raises an alert.
    ///
    /// Measured on a real installation on 2026-09-20: an exception with 18
    /// hits in a three-hour window matched nothing three hours later, because
    /// those 18 were one burst and not a rate. Frequency is not a safe proxy
    /// for "will be there next time".
    ///
    /// It is deliberately opt-in and per entry. A file where every exception
    /// is `optional` has given up the staleness check — which is why the flag
    /// belongs on the entry that needs it, next to the reason that explains
    /// why it is intermittent.
    #[serde(default)]
    pub optional: bool,
}

impl Config {
    pub fn excepted(&self, secret: &str, source: &str) -> bool {
        self.exceptions
            .iter()
            .any(|e| e.secret == secret && e.source == source)
    }

    /// Exceptions that matched nothing in this run.
    ///
    /// `optional` entries are skipped: they describe findings that come and
    /// go, so "matched nothing this time" says nothing about them.
    pub fn unused(&self, hits: &[(String, String)]) -> Vec<String> {
        self.exceptions
            .iter()
            .filter(|e| !e.optional)
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
            reason = "no longer matches anything"
            "#,
        )
        .unwrap();
        // After a run with no hit on `gone`:
        assert_eq!(c.unused(&[]), vec!["gone/journal".to_string()]);
    }

    #[test]
    fn an_optional_exception_is_never_reported_as_unused() {
        let c: Config = toml::from_str(
            r#"
            [[exception]]
            secret = "smtp-user"
            source = "journal"
            optional = true
            reason = "the mail log carries the sender only while mail is going out"
            "#,
        )
        .unwrap();
        assert!(
            c.unused(&[]).is_empty(),
            "an optional exception must survive a window in which it matches nothing"
        );
        // It still excepts when the finding does show up.
        assert!(c.excepted("smtp-user", "journal"));
    }

    #[test]
    fn optional_defaults_to_false_so_the_staleness_check_stays_on() {
        let c: Config = toml::from_str(
            r#"
            [[exception]]
            secret = "gone"
            source = "journal"
            reason = "no optional flag given"
            "#,
        )
        .unwrap();
        assert!(!c.exceptions[0].optional);
        assert_eq!(
            c.unused(&[]),
            vec!["gone/journal".to_string()],
            "leaving the flag out must not quietly disable the check"
        );
    }

    #[test]
    fn optional_and_mandatory_exceptions_coexist() {
        let c: Config = toml::from_str(
            r#"
            [[exception]]
            secret = "kommt-und-geht"
            source = "journal"
            optional = true
            reason = "intermittent by nature"

            [[exception]]
            secret = "sollte-immer-da-sein"
            source = "loki"
            reason = "steady"
            "#,
        )
        .unwrap();
        assert_eq!(
            c.unused(&[]),
            vec!["sollte-immer-da-sein/loki".to_string()],
            "only the mandatory one may be reported"
        );
    }

    #[test]
    fn a_canary_exception_is_rejected() {
        let c: Config = toml::from_str(&format!(
            r#"
            [[exception]]
            secret = "{}"
            source = "journal"
            reason = "the built-in positive control"
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
