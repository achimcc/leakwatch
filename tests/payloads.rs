//! Payloads taken verbatim from the incidents in the homeserver CLAUDE.md.
//! Each of these slipped past something that was supposed to catch it.

use leakwatch::scan::Scanner;

const KEY: &str = "8f14e45fceea167a5a36dedd4bea2543";

fn scanner() -> Scanner {
    Scanner::new(vec![("arr-radarr-apikey".into(), KEY.into())]).unwrap()
}

/// 2026-09-15, audit B14: 26 lines like this in guest journals. systemd logs
/// the description of a transient unit including argv.
#[test]
fn systemd_run_one_liner() {
    let line = format!(
        "Started [systemd-run] /run/current-system/sw/bin/curl -H 'X-Api-Key: {KEY}' http://192.0.2.11:7878/api/v3/movie"
    );
    assert_eq!(scanner().scan_line(&line).len(), 1);
}

/// 2026-09-15, audit B61: 278 lines with live arr keys in Loki, although the
/// mask was running. It missed this because `":["` sits between name and value
/// and `[` was not in its character class.
#[test]
fn caddy_json_header_form() {
    let line = format!(r#"{{"request":{{"headers":{{"X-Api-Key":["{KEY}"]}}}}}}"#);
    assert_eq!(scanner().scan_line(&line).len(), 1);
}

/// 2026-09-15, audit B61: 4235 lines, each a browser session.
#[test]
fn jellyfin_token_with_escapes() {
    let line = format!(r#"X-Emby-Authorization: MediaBrowser Client=Web, Token=\"{KEY}\""#);
    assert_eq!(scanner().scan_line(&line).len(), 1);
}

/// 2026-09-09: the passkey travelled inside an announce URL in a field called
/// `trackers`. The mask guessed by field name and never looked here.
#[test]
fn announce_url_in_a_trackers_field() {
    let line = format!(r#""trackers":["https://tracker.example/{KEY}/announce"]"#);
    assert_eq!(scanner().scan_line(&line).len(), 1);
}

/// 2026-09-14: a URL-encoded copy inside a `next=` parameter — same value,
/// different spelling of its surroundings.
#[test]
fn copy_inside_a_next_parameter() {
    let line = format!("GET /flows/-/?next=%2Fapi%2Fv3%2F%3Fapikey%3D{KEY} HTTP/1.1");
    assert_eq!(scanner().scan_line(&line).len(), 1);
}

/// The value split across a line boundary, as Loki and journald break long
/// lines.
#[test]
fn value_split_across_lines() {
    let (head, tail) = KEY.split_at(10);
    let data = format!("prefix {head}\n{tail} suffix\n");
    let mut hits = 0;
    scanner()
        .scan_stream(data.as_bytes(), &mut |_, _, _| hits += 1)
        .unwrap();
    assert_eq!(hits, 1, "not found across the line boundary");
}

/// The negative control. Without it, six green assertions are also compatible
/// with a scanner that matches almost anything — the file would prove nothing
/// about the payloads it names.
#[test]
fn the_same_shapes_without_the_key_yield_nothing() {
    let other = "3c6e0b8a9c15224a8228b9a98ca1531d";
    let s = scanner();
    for line in [
        format!("Started [systemd-run] curl -H 'X-Api-Key: {other}' http://x/"),
        format!(r#"{{"request":{{"headers":{{"X-Api-Key":["{other}"]}}}}}}"#),
        format!(r#"X-Emby-Authorization: MediaBrowser Client=Web, Token=\"{other}\""#),
        format!(r#""trackers":["https://tracker.example/{other}/announce"]"#),
        format!("GET /flows/-/?next=%2Fapi%2Fv3%2F%3Fapikey%3D{other} HTTP/1.1"),
    ] {
        assert!(
            s.scan_line(&line).is_empty(),
            "matched a line that carries a different value: {line}"
        );
    }
}
