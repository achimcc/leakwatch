//! `sieve`: text in, the same text out with every known secret — in every
//! spelling leakwatch knows — replaced by `<REDACTED:name>`, and every
//! secret-looking value in a telling context by `<REDACTED?:kind>`. The
//! name says WHICH key stood in the line; the value never does.

use std::collections::BTreeSet;

use anyhow::Result;

use crate::canary;
use crate::guess;
use crate::report::{merge, sanitize};
use crate::scan::{Hit, Scanner};
use crate::variants::base_name;

/// Names of values loaded from `/run/secrets/rendered` carry this prefix:
/// a rendered template CONTAINS secrets, so when both match the same bytes
/// the secret's name is the one worth printing.
pub const TEMPLATE_PREFIX: &str = "rendered/";

/// What a run did, for the closing line on stderr.
#[derive(Debug, Default)]
pub struct Counts {
    pub lines: u64,
    pub known: u64,
    pub guessed: u64,
    pub names: BTreeSet<String>,
}

pub struct Sieve {
    scanner: Scanner,
    guess: bool,
}

/// The merged spans of `hits` with the names to print for each.
fn named_spans(hits: &[Hit], len: usize) -> Vec<((usize, usize), String)> {
    let spans: Vec<(usize, usize)> = hits.iter().map(|(_, s)| *s).collect();
    let mut out = Vec::new();
    let mut cursor = 0;
    for (start, end) in merge(&spans) {
        let start = start.min(len).max(cursor);
        let end = end.min(len);
        if end <= start {
            continue;
        }
        let mut names: BTreeSet<&str> = hits
            .iter()
            .filter(|(_, (s, e))| *s < end && start < *e)
            .map(|(n, _)| base_name(n))
            .collect();
        if names.iter().any(|n| !n.starts_with(TEMPLATE_PREFIX)) {
            names.retain(|n| !n.starts_with(TEMPLATE_PREFIX));
        }
        let label: Vec<&str> = names.into_iter().collect();
        out.push(((start, end), label.join(",")));
        cursor = end;
    }
    out
}

fn apply(line: &str, spans: &[((usize, usize), String)]) -> String {
    let mut out = String::with_capacity(line.len());
    let mut cursor = 0;
    for ((start, end), mask) in spans {
        out.push_str(&line[cursor..*start]);
        out.push_str(mask);
        cursor = *end;
    }
    out.push_str(&line[cursor..]);
    out
}

/// Replaces every hit span with `<REDACTED:names>`; returns the text and the
/// names printed, one entry per merged span.
pub fn redact_named(line: &str, hits: &[Hit]) -> (String, Vec<String>) {
    let named = named_spans(hits, line.len());
    let printed: Vec<String> = named.iter().map(|(_, n)| n.clone()).collect();
    let masks: Vec<((usize, usize), String)> = named
        .into_iter()
        .map(|(sp, n)| (sp, format!("<REDACTED:{n}>")))
        .collect();
    (apply(line, &masks), printed)
}

impl Sieve {
    /// The canary values go in beside the real ones, so [`Sieve::prove`]
    /// and a canary in the input both have something to find.
    pub fn new(mut values: Vec<(String, String)>, guess: bool) -> Result<Sieve> {
        values.extend(canary::secrets());
        Ok(Sieve {
            scanner: Scanner::new(values)?,
            guess,
        })
    }

    pub fn scanner(&self) -> &Scanner {
        &self.scanner
    }

    /// Every probe line — the canary in every spelling — through the sieve;
    /// a canary value that survives means the sieve must not print anything.
    pub fn prove(&self) -> std::result::Result<(), String> {
        for p in canary::probes(&self.scanner) {
            let mut c = Counts::default();
            let out = self.sieve_line(p.text(), &mut c);
            let survived = [canary::CANARY_VALUE, canary::CANARY_VALUE_ENCODED]
                .iter()
                .any(|v| out.contains(v))
                || crate::variants::lines(canary::CANARY_VALUE_MULTILINE)
                    .iter()
                    .any(|l| out.contains(l.as_str()))
                || c.known == 0;
            if survived {
                return Err(format!(
                    "canary probe {} survived the sieve — refusing to print",
                    p.kind.suffix()
                ));
            }
        }
        Ok(())
    }

    /// One line in, one line out. Both layers look at the ORIGINAL line:
    /// the known values decide first, a guess that overlaps a known span is
    /// dropped — and so the mask `<REDACTED:x>` can never be re-matched as
    /// a bearer token by the guess layer.
    pub fn sieve_line(&self, line: &str, counts: &mut Counts) -> String {
        counts.lines += 1;
        let hits = self.scanner.scan_line(line);
        let named = named_spans(&hits, line.len());
        counts.known += named.len() as u64;
        let mut masks: Vec<((usize, usize), String)> = Vec::new();
        for ((s, e), n) in &named {
            for part in n.split(',') {
                counts.names.insert(part.to_string());
            }
            masks.push(((*s, *e), format!("<REDACTED:{n}>")));
        }
        if self.guess {
            for ((s, e), kind) in guess::spans(line) {
                if named.iter().any(|((ks, ke), _)| s < *ke && *ks < e) {
                    continue;
                }
                counts.guessed += 1;
                masks.push(((s, e), format!("<REDACTED?:{kind}>")));
            }
            masks.sort_by_key(|((s, _), _)| *s);
        }
        sanitize(&apply(line, &masks))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canary;

    const A: &str = "alpha-secret-value-0123456789";
    const B: &str = "bravo-secret-value-9876543210";

    fn sieve(values: Vec<(&str, &str)>, guess: bool) -> Sieve {
        Sieve::new(
            values
                .into_iter()
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .collect(),
            guess,
        )
        .unwrap()
    }

    fn run(s: &Sieve, line: &str) -> (String, Counts) {
        let mut c = Counts::default();
        let out = s.sieve_line(line, &mut c);
        (out, c)
    }

    #[test]
    fn known_value_masked_with_name() {
        let s = sieve(vec![("smtp-pass", A)], true);
        let (out, c) = run(&s, &format!("login with {A} now"));
        assert_eq!(out, "login with <REDACTED:smtp-pass> now");
        assert_eq!((c.lines, c.known, c.guessed), (1, 1, 0));
        assert!(c.names.contains("smtp-pass"));
    }

    #[test]
    fn two_spellings_one_name() {
        let s = sieve(vec![("x", A)], true);
        let enc =
            crate::variants::percent(A.as_bytes(), crate::variants::URI_COMPONENT, true, false);
        let (out, c) = run(&s, &format!("a={A} b={enc}"));
        assert!(!out.contains(A), "{out}");
        assert_eq!(out.matches("<REDACTED:x>").count(), 2, "{out}");
        assert_eq!(c.known, 2);
        assert_eq!(c.names.len(), 1);
    }

    #[test]
    fn template_name_yields_to_secret() {
        let tpl = format!("SMTP_PASSWORD={A}\nOTHER=1");
        let s = sieve(
            vec![("smtp-pass", A), ("rendered/alertmanager-env", &tpl)],
            true,
        );
        let (out, _) = run(&s, &format!("env: SMTP_PASSWORD={A} ok"));
        assert!(out.contains("<REDACTED:smtp-pass>"), "{out}");
        assert!(!out.contains("rendered/"), "{out}");
        assert!(!out.contains(A), "{out}");
    }

    #[test]
    fn two_distinct_secrets_overlapping_list_both() {
        let ab = format!("{A}{B}");
        let s = sieve(vec![("a", A), ("ab", &ab)], true);
        let (out, _) = run(&s, &format!("x {ab} y"));
        assert_eq!(out, "x <REDACTED:a,ab> y");
    }

    #[test]
    fn guess_runs_after_known() {
        let s = sieve(vec![("tok", A)], true);
        let (out, c) = run(&s, &format!("Authorization: Bearer {A}"));
        assert_eq!(out, "Authorization: Bearer <REDACTED:tok>");
        assert_eq!((c.known, c.guessed), (1, 0));
        let (out, c) = run(&s, "Authorization: Bearer unknown-token-xyz");
        assert_eq!(out, "Authorization: Bearer <REDACTED?:header>");
        assert_eq!((c.known, c.guessed), (0, 1));
        let s = sieve(vec![("tok", A)], false);
        let (out, _) = run(&s, "Authorization: Bearer unknown-token-xyz");
        assert_eq!(out, "Authorization: Bearer unknown-token-xyz");
    }

    #[test]
    fn canary_probes_all_pass() {
        let s = sieve(vec![("x", A)], true);
        s.prove().unwrap();
        let s = sieve(vec![("x", A)], false);
        s.prove().unwrap();
    }

    #[test]
    fn canary_in_input_is_masked_by_name() {
        let s = sieve(vec![("x", A)], true);
        let (out, _) = run(&s, &format!("saw {}", canary::CANARY_VALUE));
        assert_eq!(out, "saw <REDACTED:leakwatch-canary>");
    }

    #[test]
    fn output_never_contains_a_canary_value() {
        let s = sieve(vec![("x", A)], true);
        for p in canary::probes(s.scanner()) {
            let (out, _) = run(&s, p.text());
            for v in [canary::CANARY_VALUE, canary::CANARY_VALUE_ENCODED] {
                assert!(!out.contains(v), "{out}");
            }
            for l in crate::variants::lines(canary::CANARY_VALUE_MULTILINE) {
                assert!(!out.contains(&l), "{out}");
            }
        }
    }

    #[test]
    fn control_characters_do_not_pass() {
        let s = sieve(vec![("x", A)], true);
        let (out, _) = run(&s, "a\u{1b}[2Jb");
        assert!(!out.contains('\u{1b}'), "{out:?}");
    }
}
