//! Regression tests for the findings of audit 3 (2026-09-27), class A2.
//! Only invented values.
//!
//! - A2-1 / B70: a report masked only its own span — the other occurrences and
//!   the other secrets of the same line came out in plaintext.
//! - A2-3 / WG-7 / B88: only the literal value was searched; Base64, percent-,
//!   JSON- and hex-encoded copies were not found.

use leakwatch::report::{self, Finding, MASK};
use leakwatch::scan::{Hit, Scanner};
use leakwatch::variants::{self, B64_STD, B64_URL, JsonStyle, Kind};
use proptest::prelude::*;

const WERT: &str = "Zq7Xw2mP9vK4tR8sL1nB";
const WERT2: &str = "hH3jJ5kK7lL9zZ1xX3cC";

fn sc() -> Scanner {
    Scanner::new(vec![
        ("probe-a".into(), WERT.into()),
        ("probe-b".into(), WERT2.into()),
    ])
    .unwrap()
}

/// Every rendered report for a text, the way `leakwatch` builds them: all
/// spans masked once, then one finding per hit — with and without context.
fn reports(scanner: &Scanner, data: &str) -> Vec<String> {
    let mut out = Vec::new();
    scanner
        .scan_stream_grouped(data.as_bytes(), &mut |text, hits: &[Hit], all| {
            for f in Finding::from_hits(text, hits, all, "journal", "g/u", "0") {
                out.push(report::format(&f));
                out.push(report::format_brief(&f));
                out.push(format!("{f:?}"));
            }
        })
        .unwrap();
    out
}

// ---------------------------------------------------------------- A2-1 / B70

#[test]
fn the_same_value_twice_in_one_line_is_masked_twice() {
    let line = format!("GET /api?apikey={WERT}&retry_key={WERT} HTTP/1.1");
    let out = reports(&sc(), &line);
    assert_eq!(out.len(), 6, "two findings, three renderings each");
    for r in &out {
        assert!(
            !r.contains(WERT),
            "report leaks the value: {}",
            r.replace(WERT, "<<W>>")
        );
    }
    assert!(
        out[0].contains(&format!("apikey={MASK}&retry_key={MASK}")),
        "{}",
        out[0]
    );
}

#[test]
fn two_secrets_in_one_line_mask_each_other() {
    let line = format!("xtream login user={WERT2} pass={WERT}");
    for r in reports(&sc(), &line) {
        assert!(
            !r.contains(WERT) && !r.contains(WERT2),
            "neighbour leaks: {r:?}"
        );
    }
}

#[test]
fn a_secret_inside_another_is_masked_as_a_whole() {
    // A rendered URL holding a password: both patterns hit, overlapping.
    let pw = "Pw9sEcr3tXyZ";
    let url = format!("https://u:{pw}@db.example/x");
    let s = Scanner::new(vec![("pw".into(), pw.into()), ("url".into(), url.clone())]).unwrap();
    let names: Vec<String> = s
        .scan_line(&format!("connect {url} ok"))
        .into_iter()
        .map(|h| h.0)
        .collect();
    assert!(
        names.contains(&"pw".to_string()) && names.contains(&"url".to_string()),
        "{names:?}"
    );
    for r in reports(&s, &format!("connect {url} ok")) {
        assert!(
            !r.contains("db.example/x"),
            "tail of the outer secret survived: {r}"
        );
        assert!(!r.contains(pw));
    }
}

#[test]
fn the_brief_form_carries_no_line_content() {
    let line = format!("very-distinct-context-word user={WERT2} pass={WERT}");
    let s = sc();
    let hits = s.scan_line(&line);
    let spans: Vec<(usize, usize)> = hits.iter().map(|h| h.1).collect();
    for f in Finding::from_hits(
        &line,
        &hits,
        &spans,
        "journal",
        "media-01 radarr.service",
        "1758300000",
    ) {
        let brief = report::format_brief(&f);
        assert!(!brief.contains("very-distinct-context-word"), "{brief}");
        assert!(
            !brief.contains(MASK),
            "no line at all, not even a redacted one: {brief}"
        );
        assert!(brief.contains("radarr.service"));
        assert!(brief.contains("just rotor-leser probe-"));
    }
}

#[test]
fn control_characters_do_not_reach_the_report() {
    let line = format!("\x1b]52;c;SGFjaw==\x07 {WERT} \x1b[2J");
    for r in reports(&sc(), &line) {
        assert!(
            !r.contains('\x1b') && !r.contains('\x07'),
            "{:?}",
            r.replace(WERT, "<W>")
        );
    }
}

#[test]
fn a_hit_across_a_line_seam_masks_everything_in_the_joined_text() {
    // WERT2 sits entirely in the first line; WERT is split across the seam.
    let (head, tail) = WERT.split_at(7);
    let data = format!("user={WERT2} pass={head}\n{tail} end\n");
    let out = reports(&sc(), &data);
    assert!(!out.is_empty());
    for r in out {
        assert!(!r.contains(WERT) && !r.contains(WERT2), "{r:?}");
    }
}

fn value_strategy() -> impl Strategy<Value = String> {
    // No `<`/`>`: a value containing the mask's brackets could be formed ACROSS
    // a mask — a property of the test, not of the tool.
    "[A-Za-z0-9@/&\"%+= ._:~-]{8,24}"
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// For any line with n occurrences of any of the patterns — plain or in
    /// any encoded spelling — no rendering of any finding contains any
    /// pattern.
    #[test]
    fn no_report_ever_contains_a_pattern(
        values in prop::collection::vec(value_strategy(), 1..4),
        pieces in prop::collection::vec(("[ -~äöü\t\x1b]{0,20}", any::<prop::sample::Index>(), any::<prop::sample::Index>()), 1..6),
    ) {
        let secrets: Vec<(String, String)> = values
            .iter()
            .enumerate()
            .map(|(i, v)| (format!("s{i}"), v.clone()))
            .collect();
        let scanner = Scanner::new(secrets).unwrap();
        // Every pattern the scanner builds: the trimmed value and its spellings.
        let mut patterns: Vec<String> = Vec::new();
        for v in &values {
            let v = v.trim();
            if v.len() < variants::MIN_LEN { continue; }
            patterns.push(v.to_string());
            patterns.extend(variants::spellings(v).into_iter().map(|(_, s)| s));
        }
        prop_assume!(!patterns.is_empty());
        let mut line = String::new();
        for (filler, pick, _) in &pieces {
            line.push_str(filler);
            line.push_str(&patterns[pick.index(patterns.len())]);
        }
        line.push_str(" end");
        for r in reports(&scanner, &line) {
            for p in &patterns {
                prop_assert!(!r.contains(p.as_str()), "pattern in report: {:?}", r);
            }
        }
    }
}

// ------------------------------------------------------- A2-3 / WG-7 / B88

fn found(s: &Scanner, text: &str, name: &str) -> bool {
    s.scan_line(text).iter().any(|(n, _)| n == name)
}

#[test]
fn encoded_copies_are_found_and_named_by_their_spelling() {
    let s = sc();
    let basic = variants::b64(format!("user:{WERT}").as_bytes(), B64_STD);
    assert!(found(
        &s,
        &format!("Authorization: Basic {basic}"),
        "probe-a[b64]"
    ));
    let basic_alone = variants::b64(WERT.as_bytes(), B64_STD);
    assert!(found(&s, &format!("token={basic_alone}"), "probe-a[b64]"));
    let hex_lo: String = WERT.bytes().map(|b| format!("{b:02x}")).collect();
    let hex_up: String = WERT.bytes().map(|b| format!("{b:02X}")).collect();
    assert!(found(&s, &hex_lo, "probe-a[hex]"));
    assert!(found(&s, &hex_up, "probe-a[hex]"));
}

#[test]
fn every_base64_alignment_is_found() {
    let s = sc();
    for prefix in ["", "u", "u:", "user:", "admin:x"] {
        let enc = variants::b64(format!("{prefix}{WERT}\n").as_bytes(), B64_STD);
        assert!(found(&s, &enc, "probe-a[b64]"), "prefix {prefix:?}: {enc}");
    }
}

#[test]
fn urlsafe_base64_is_found() {
    // Bytes that encode to `+`/`/` in the standard alphabet.
    let v = "~~~secret-value~~~?>?";
    let s = Scanner::new(vec![("k".into(), v.into())]).unwrap();
    let enc = variants::b64(v.as_bytes(), B64_URL);
    assert!(enc.contains('-') || enc.contains('_'), "{enc}");
    assert!(found(&s, &format!("jwt.{enc}."), "k[b64url]"), "{enc}");
}

#[test]
fn percent_encoded_copies_are_found() {
    let v = "p@ss/Zq7Xw2mP9vK4 tR8sL1nB";
    let s = Scanner::new(vec![("url-probe".into(), v.into())]).unwrap();
    let upper: String = v
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    assert!(
        found(&s, &format!("GET /?pw={upper}"), "url-probe[url]"),
        "{upper}"
    );
    let lower = upper.replace("%2F", "%2f");
    assert!(found(&s, &format!("GET /?pw={lower}"), "url-probe[url]"));
    // Python's quote() keeps the slash; forms put `+` for a space.
    assert!(found(
        &s,
        "GET /?pw=p%40ss/Zq7Xw2mP9vK4%20tR8sL1nB",
        "url-probe[url]"
    ));
    assert!(found(
        &s,
        "pw=p%40ss%2FZq7Xw2mP9vK4+tR8sL1nB&x",
        "url-probe[url]"
    ));
}

#[test]
fn json_escaped_copies_are_found() {
    let v = "p&ss\"Zq7Xw2mP9vK4t/R8sL1nB";
    let s = Scanner::new(vec![("json-probe".into(), v.into())]).unwrap();
    // Go: `&` as &.
    assert!(found(
        &s,
        "{\"pw\":\"p\\u0026ss\\\"Zq7Xw2mP9vK4t/R8sL1nB\"}",
        "json-probe[json]"
    ));
    // serde_json / Python ensure_ascii=False.
    let serde = serde_json::to_string(v).unwrap();
    assert!(
        found(&s, &format!("{{\"pw\":{serde}}}"), "json-probe[json]"),
        "{serde}"
    );
    // PHP: `/` as `\/`.
    assert!(found(
        &s,
        &variants::json(v, JsonStyle::Slash),
        "json-probe[json]"
    ));
}

#[test]
fn a_multiline_value_is_found_line_by_line_and_json_escaped() {
    let pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\n-----END PRIVATE KEY-----";
    let s = Scanner::new(vec![("tls-key".into(), pem.into())]).unwrap();
    assert!(found(
        &s,
        "  MIIEvQIBADANBgkqhkiG9w0BAQEFAASC",
        "tls-key[line]"
    ));
    let serde = serde_json::to_string(pem).unwrap();
    assert!(found(&s, &format!("{{\"key\":{serde}}}"), "tls-key[json]"));
}

#[test]
fn variants_do_not_raise_false_alarms() {
    let pem =
        "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----";
    let tpl = "[Interface]\nLOG_LEVEL=information\nListenPort = 51820";
    let s = Scanner::new(vec![
        ("tls-key".into(), pem.into()),
        ("wg".into(), tpl.into()),
        // Too short raw — must not come back as hex or Base64.
        ("kurz".into(), "admin1".into()),
    ])
    .unwrap();
    assert!(
        s.scan_line("-----BEGIN PRIVATE KEY----- of some other key")
            .is_empty()
    );
    assert!(s.scan_line("[Interface] LOG_LEVEL=information").is_empty());
    assert!(s.scan_line(&variants::hex(b"admin1", false)).is_empty());
    assert!(s.scan_line(&variants::b64(b"admin1", B64_STD)).is_empty());
    assert_eq!(s.pattern_count(), 2, "the short value counts as skipped");
}

#[test]
fn every_variant_name_maps_back_to_the_secret() {
    let s = sc();
    for k in s.kinds_of("probe-a") {
        assert_eq!(variants::base_name(&k.name("probe-a")), "probe-a");
    }
    assert!(s.kinds_of("probe-a").contains(&Kind::B64));
}
