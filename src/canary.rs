//! The positive control. Without it "0 findings" cannot be told apart from
//! "the scanner is broken" — and a silent sensor looks like a quiet day.
//!
//! IT RUNS PER ADAPTER, not once per run: a broken Loki path must not be
//! covered by a healthy journal path.
//!
//! AND PER SPELLING: the canary goes into the stream plain, Base64-encoded in
//! all three alignments, percent-encoded, JSON-escaped, hex-dumped and as
//! single lines of a multi-line value, and each probe line has to come back
//! with a hit of ITS spelling. A pattern builder that silently stopped
//! producing one encoding would otherwise leave that encoding unsearched
//! behind a green canary.

use crate::scan::{Hit, Scanner};
use crate::variants::{self, JsonStyle, Kind};
use std::io::{BufRead, Read};

pub const CANARY_NAME: &str = "leakwatch-canary";
/// Not a real secret. It exists so a run can prove it is able to find one.
pub const CANARY_VALUE: &str = "leakwatch-canary-4f8a2be71d0c9356";
/// The same, with every character an encoder changes — `/`, `&`, `"`, `<`,
/// a space, a non-ASCII letter — so each percent- and JSON-spelling differs
/// from the plain value and gets a pattern of its own to prove.
pub const CANARY_VALUE_ENCODED: &str = "leakwatch/canary&\"7c1e 90ab<d3f5>é2468";
/// A multi-line canary, for the per-line patterns of multi-line values.
pub const CANARY_VALUE_MULTILINE: &str = "-----BEGIN LEAKWATCH CANARY-----\nleakwatchCanaryLine7e3a9c1f5b2d8e04\nleakwatchCanaryLine0d6b4f2a8c1e9357\n-----END LEAKWATCH CANARY-----";

/// Every canary value, all under [`CANARY_NAME`], to go into the scanner
/// alongside the real secrets.
pub fn secrets() -> Vec<(String, String)> {
    [CANARY_VALUE, CANARY_VALUE_ENCODED, CANARY_VALUE_MULTILINE]
        .iter()
        .map(|v| (CANARY_NAME.to_string(), v.to_string()))
        .collect()
}

/// Does this scanner carry the canary at all?
pub fn check(scanner: &Scanner) -> bool {
    !scanner
        .scan_line(&format!("probe {CANARY_VALUE} probe"))
        .is_empty()
}

/// One injected line: which spelling it carries.
#[derive(Clone, Debug)]
pub struct Probe {
    pub kind: Kind,
    line: String,
}

/// The probe lines for the kinds `scanner` carries for the canary.
///
/// EACH IS A REAL EMBEDDING, not the pattern itself: `base64("u:" + value +
/// "!")` for each of the three byte alignments, the value percent-encoded in
/// a query string, JSON-escaped inside an object, hex-dumped — encoded as a
/// whole, the way a service would, so a wrong window or a missing alignment
/// in the pattern builder shows up as a probe that was not found.
pub fn probes(scanner: &Scanner) -> Vec<Probe> {
    let kinds = scanner.kinds_of(CANARY_NAME);
    let mut raw: Vec<(Kind, String)> = Vec::new();
    raw.push((Kind::Plain, format!("value={CANARY_VALUE};")));
    for (kind, alphabet) in [
        (Kind::B64, variants::B64_STD),
        (Kind::B64Url, variants::B64_URL),
    ] {
        for prefix in ["", "u", "u:"] {
            for v in [CANARY_VALUE, CANARY_VALUE_ENCODED] {
                let data = format!("{prefix}{v}!");
                raw.push((
                    kind,
                    format!("Basic {}", variants::b64(data.as_bytes(), alphabet)),
                ));
            }
        }
    }
    let e = CANARY_VALUE_ENCODED.as_bytes();
    raw.push((
        Kind::Url,
        format!(
            "GET /?pw={}&x=1",
            variants::percent(e, variants::UNRESERVED, true, false)
        ),
    ));
    raw.push((
        Kind::Url,
        format!(
            "GET /?pw={}&x=1",
            variants::percent(e, variants::UNRESERVED, false, false)
        ),
    ));
    raw.push((
        Kind::Url,
        format!(
            "GET /?pw={}&x=1",
            variants::percent(e, variants::UNRESERVED_SLASH, true, false)
        ),
    ));
    raw.push((
        Kind::Url,
        format!(
            "GET /?pw={}&x=1",
            variants::percent(e, variants::URI_COMPONENT, true, false)
        ),
    ));
    raw.push((
        Kind::Url,
        format!(
            "pw={}&x=1",
            variants::percent(e, variants::FORM, true, true)
        ),
    ));
    for style in [
        JsonStyle::Standard,
        JsonStyle::Slash,
        JsonStyle::HtmlSafe,
        JsonStyle::Ascii,
    ] {
        raw.push((
            Kind::Json,
            format!(
                "{{\"pw\":\"{}\"}}",
                variants::json(CANARY_VALUE_ENCODED, style)
            ),
        ));
        // A multi-line value inside JSON is ONE line in a log.
        raw.push((
            Kind::Json,
            format!(
                "{{\"pem\":\"{}\"}}",
                variants::json(CANARY_VALUE_MULTILINE, style)
            ),
        ));
    }
    for upper in [false, true] {
        raw.push((
            Kind::Hex,
            format!("dump {}", variants::hex(CANARY_VALUE.as_bytes(), upper)),
        ));
    }
    for l in variants::lines(CANARY_VALUE_MULTILINE) {
        raw.push((Kind::Line, format!("  {l}")));
    }
    raw.into_iter()
        .filter(|(k, _)| kinds.contains(k))
        .enumerate()
        .map(|(i, (kind, body))| Probe {
            kind,
            line: format!("leakwatch-probe[{i}] {body}"),
        })
        .collect()
}

/// Mix the probe lines into a stream, ahead of it, so the scanner and the
/// formatter are exercised on real input.
///
/// WHAT THIS DOES NOT COVER: the probe lines come from memory, chained ahead
/// of the source. A source whose command failed and produced no lines at all
/// still yields found probes. Proving the SOURCE delivered something is the
/// job of the line count — see [`source_was_silent`].
pub fn inject<R: BufRead>(probes: &[Probe], r: R) -> impl BufRead {
    let mut text = String::new();
    for p in probes {
        text.push_str(&p.line);
        text.push('\n');
    }
    std::io::BufReader::new(std::io::Cursor::new(text.into_bytes()).chain(r))
}

/// Which probe, if `text` is a probe line.
pub fn probe_index(text: &str) -> Option<usize> {
    let rest = text.strip_prefix("leakwatch-probe[")?;
    let (n, _) = rest.split_once(']')?;
    n.parse().ok()
}

/// Kinds that stand in for each other when proving a probe. A URL-safe
/// window without `-`/`_` is the same string as the standard one and only
/// exists once in the automaton, under `[b64]`.
fn same_family(probe: Kind, hit: Kind) -> bool {
    probe == hit
        || matches!(
            (probe, hit),
            (Kind::B64Url, Kind::B64) | (Kind::B64, Kind::B64Url)
        )
}

/// Does `hits` (found in probe line `probe`) prove it?
pub fn proves(probe: &Probe, hits: &[Hit]) -> bool {
    hits.iter().any(|(name, _)| {
        variants::base_name(name) == CANARY_NAME && same_family(probe.kind, Kind::of(name))
    })
}

/// Did the source deliver anything of its own?
///
/// `scan_stream` returns the number of lines it read, and `injected` of
/// those are the probe lines this module put in front. A count no higher
/// than that means the source itself was silent — which, for a
/// command-backed adapter, is a tool failure wearing the costume of a clean
/// result.
pub fn source_was_silent(lines_read: u64, injected: usize) -> bool {
    lines_read <= injected as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::Scanner;

    fn with_canary() -> Scanner {
        Scanner::new(secrets()).unwrap()
    }

    #[test]
    fn check_passes_when_the_scanner_can_find_the_canary() {
        assert!(check(&with_canary()));
    }

    #[test]
    fn check_fails_when_the_canary_is_missing_from_the_patterns() {
        let s = Scanner::new(vec![("other".into(), "abc123def456".into())]).unwrap();
        assert!(!check(&s), "a scanner without the canary must not pass");
    }

    #[test]
    fn the_canary_scanner_carries_every_kind() {
        let kinds = with_canary().kinds_of(CANARY_NAME);
        for k in variants::ALL_KINDS {
            assert!(kinds.contains(&k), "no canary pattern of kind {k:?}");
        }
    }

    #[test]
    fn every_probe_is_proven_by_its_own_line() {
        let s = with_canary();
        let probes = probes(&s);
        assert!(probes.len() >= 20, "only {} probes", probes.len());
        for p in &probes {
            let hits = s.scan_line(&p.line);
            assert!(proves(p, &hits), "probe {p:?} not proven: {hits:?}");
        }
        // Every kind has at least one probe.
        for k in variants::ALL_KINDS {
            assert!(probes.iter().any(|p| p.kind == k), "no probe for {k:?}");
        }
    }

    #[test]
    fn a_probe_is_proven_only_by_its_own_spelling() {
        // A plaintext hit must not prove the Base64 probe, or the per-variant
        // control proves nothing about the Base64 patterns.
        let s = with_canary();
        let b64 = probes(&s)
            .into_iter()
            .find(|p| p.kind == Kind::B64)
            .unwrap();
        let hits = s.scan_line(&b64.line);
        assert!(proves(&b64, &hits));
        let plain_only: Vec<Hit> = hits
            .into_iter()
            .filter(|(n, _)| Kind::of(n) == Kind::Plain)
            .collect();
        assert!(!proves(&b64, &plain_only));
        // And a scanner whose canary differs proves none of the probes.
        let other =
            Scanner::new(vec![(CANARY_NAME.into(), "some-other-value-123456".into())]).unwrap();
        for p in probes(&s) {
            assert!(!proves(&p, &other.scan_line(&p.line)), "{p:?}");
        }
    }

    #[test]
    fn inject_adds_every_probe_line_to_a_stream() {
        let s = with_canary();
        let probes = probes(&s);
        let data = "a\nb\n";
        let mut out = String::new();
        std::io::Read::read_to_string(&mut inject(&probes, data.as_bytes()), &mut out).unwrap();
        assert_eq!(out.lines().count(), probes.len() + 2);
        assert_eq!(probe_index(out.lines().next().unwrap()), Some(0));
        assert!(out.ends_with("a\nb\n"));
    }

    #[test]
    fn the_canary_is_long_enough_to_be_searched_for() {
        // Shorter than MIN_LEN in scan.rs would make the control check nothing.
        assert!(CANARY_VALUE.len() >= 16);
    }

    #[test]
    fn source_was_silent_when_only_the_probes_arrived() {
        assert!(source_was_silent(0, 5));
        assert!(source_was_silent(5, 5));
        assert!(!source_was_silent(6, 5));
    }
}
