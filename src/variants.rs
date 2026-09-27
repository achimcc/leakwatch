//! Encoded spellings of a value — the forms a secret actually takes in a log.
//!
//! WHY: the plaintext matcher finds exactly the bytes it is given, and logs
//! rarely carry exactly those bytes. `Authorization: Basic` is Base64 of
//! `user:password`; an HTTP access log carries a password with `@` or `/`
//! percent-encoded; Loki's JSON escapes `"` and `/`; a hex dump spells every
//! byte twice. A run that searched only the plaintext answered "0 findings,
//! canary ok" for all of these (audit 3, A2-3 / WG-7).
//!
//! Each variant gets its own pattern in the same automaton, named
//! `<secret>[<kind>]`, so a report says WHICH spelling leaked while the
//! metric and the exceptions keep keying on the secret's own name
//! ([`base_name`]).
//!
//! FALSE ALARMS: a variant is subject to the same minimum length as a raw
//! value, and variants are only built for values that pass that minimum
//! themselves — a six-byte password does not come back through the back door
//! as a twelve-character hex string. Lines of a multi-line value are only
//! taken when they look like key material (see [`lines`]).

/// The kind of spelling a pattern searches for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    Plain,
    /// Standard Base64, in all three byte alignments.
    B64,
    /// URL-safe Base64 (`-_` instead of `+/`), in all three byte alignments.
    B64Url,
    /// Percent-encoding (several common "safe" sets, upper- and lowercase).
    Url,
    /// JSON string escapes (standard, `\/`, HTML-safe `<`, ASCII-only).
    Json,
    /// Hex of the UTF-8 bytes, lower- and uppercase.
    Hex,
    /// A single line of a multi-line value.
    Line,
}

pub const ALL_KINDS: [Kind; 7] = [
    Kind::Plain,
    Kind::B64,
    Kind::B64Url,
    Kind::Url,
    Kind::Json,
    Kind::Hex,
    Kind::Line,
];

impl Kind {
    pub fn suffix(self) -> &'static str {
        match self {
            Kind::Plain => "",
            Kind::B64 => "b64",
            Kind::B64Url => "b64url",
            Kind::Url => "url",
            Kind::Json => "json",
            Kind::Hex => "hex",
            Kind::Line => "line",
        }
    }

    /// The pattern name for a secret in this spelling.
    pub fn name(self, secret: &str) -> String {
        match self {
            Kind::Plain => secret.to_string(),
            k => format!("{secret}[{}]", k.suffix()),
        }
    }

    /// Which kind a pattern name carries.
    pub fn of(name: &str) -> Kind {
        for k in ALL_KINDS {
            if k != Kind::Plain && name.ends_with(&format!("[{}]", k.suffix())) {
                return k;
            }
        }
        Kind::Plain
    }
}

/// The secret's own name, without a variant suffix: `radarr-apikey[b64]` →
/// `radarr-apikey`. Only the suffixes this module produces are stripped.
pub fn base_name(name: &str) -> &str {
    match Kind::of(name) {
        Kind::Plain => name,
        k => &name[..name.len() - k.suffix().len() - 2],
    }
}

/// A value must be at least this long to be searched for — raw or encoded.
pub const MIN_LEN: usize = 8;

/// A LINE of a multi-line value must be at least this long, and shaped like
/// key material, before it becomes its own pattern. See [`lines`].
pub const LINE_MIN_LEN: usize = 16;

/// Every encoded spelling of `value` that differs from the value itself,
/// deduplicated, each at least [`MIN_LEN`] long.
pub fn spellings(value: &str) -> Vec<(Kind, String)> {
    let bytes = value.as_bytes();
    let mut out: Vec<(Kind, String)> = Vec::new();
    let mut push = |k: Kind, s: String| {
        if s.len() >= MIN_LEN && s != value && !out.iter().any(|(_, o)| *o == s) {
            out.push((k, s));
        }
    };
    for w in b64_windows(bytes, B64_STD) {
        push(Kind::B64, w);
    }
    for w in b64_windows(bytes, B64_URL) {
        push(Kind::B64Url, w);
    }
    for (safe, upper, plus) in [
        (UNRESERVED, true, false),
        (UNRESERVED, false, false),
        // Python's quote(): keeps `/`.
        (UNRESERVED_SLASH, true, false),
        // JavaScript's encodeURIComponent: keeps `!'()*`.
        (URI_COMPONENT, true, false),
        // application/x-www-form-urlencoded: space as `+`.
        (FORM, true, true),
    ] {
        push(Kind::Url, percent(bytes, safe, upper, plus));
    }
    push(Kind::Json, json(value, JsonStyle::Standard));
    push(Kind::Json, json(value, JsonStyle::Slash));
    push(Kind::Json, json(value, JsonStyle::HtmlSafe));
    push(Kind::Json, json(value, JsonStyle::Ascii));
    push(Kind::Hex, hex(bytes, false));
    push(Kind::Hex, hex(bytes, true));
    out
}

/// The single lines of a multi-line value that are searched on their own.
///
/// NOT EVERY LINE: `-----BEGIN PRIVATE KEY-----` would match every PEM file,
/// `[Interface]` every WireGuard configuration, `LOG_LEVEL=info` half of the
/// rendered templates. A line is taken only if it is at least
/// [`LINE_MIN_LEN`] long, consists only of Base64/token characters (with `=`
/// allowed only as trailing padding), and mixes letters with digits — the
/// shape of a PEM body line or a key, not of a header, a URL or an
/// assignment.
pub fn lines(value: &str) -> Vec<String> {
    if !value.contains('\n') {
        return Vec::new();
    }
    let mut out: Vec<String> = Vec::new();
    for l in value.lines() {
        let l = l.trim();
        if l.len() < LINE_MIN_LEN || l.starts_with("-----") {
            continue;
        }
        let body = l.trim_end_matches('=');
        let token = body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'_' | b'-'));
        let letters = body.bytes().any(|b| b.is_ascii_alphabetic());
        let digits = body.bytes().any(|b| b.is_ascii_digit());
        if token && letters && digits && !out.iter().any(|o| o == l) {
            out.push(l.to_string());
        }
    }
    out
}

pub const B64_STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
pub const B64_URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Plain Base64 with `=` padding.
pub fn b64(bytes: &[u8], alphabet: &[u8; 64]) -> String {
    let mut o = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for c in bytes.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                o.push(alphabet[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                o.push('=');
            }
        }
    }
    o
}

/// The part of the Base64 encoding of `bytes` that does not depend on what
/// surrounds them, for each of the three positions the value can take
/// relative to a 3-byte group — so `base64("user:" + value)` is found as well
/// as `base64(value)`.
///
/// For alignment `k` (the value starts `k` bytes into a group) the first
/// characters mix bits of the unknown prefix and are dropped (none, two or
/// three), and so is the last, partial group, whose characters depend on the
/// unknown suffix.
pub fn b64_windows(bytes: &[u8], alphabet: &[u8; 64]) -> Vec<String> {
    let mut out = Vec::new();
    for k in 0..3usize {
        let mut padded = vec![0u8; k];
        padded.extend_from_slice(bytes);
        let enc = b64(&padded, alphabet);
        let skip = [0, 2, 3][k];
        let keep = padded.len() / 3 * 4;
        if keep > skip {
            out.push(enc[skip..keep].to_string());
        }
    }
    out
}

pub type Safe = fn(u8) -> bool;

fn unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}
fn unreserved_slash(b: u8) -> bool {
    unreserved(b) || b == b'/'
}
fn uri_component(b: u8) -> bool {
    unreserved(b) || matches!(b, b'!' | b'\'' | b'(' | b')' | b'*')
}
fn form(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'*')
}

pub const UNRESERVED: Safe = unreserved;
pub const UNRESERVED_SLASH: Safe = unreserved_slash;
pub const URI_COMPONENT: Safe = uri_component;
pub const FORM: Safe = form;

/// Percent-encode every byte not in `safe`.
pub fn percent(bytes: &[u8], safe: Safe, upper: bool, plus_for_space: bool) -> String {
    let mut o = String::with_capacity(bytes.len() * 3);
    for &b in bytes {
        if safe(b) {
            o.push(b as char);
        } else if plus_for_space && b == b' ' {
            o.push('+');
        } else if upper {
            o.push_str(&format!("%{b:02X}"));
        } else {
            o.push_str(&format!("%{b:02x}"));
        }
    }
    o
}

#[derive(Clone, Copy)]
pub enum JsonStyle {
    /// What serde_json, Python's `ensure_ascii=False` and most encoders write.
    Standard,
    /// Additionally `/` as `\/` (PHP, some Java encoders).
    Slash,
    /// Additionally `<`, `>`, `&`, U+2028, U+2029 as `\uXXXX` (Go).
    HtmlSafe,
    /// Every non-ASCII character as `\uXXXX` (Python's default).
    Ascii,
}

/// The inside of a JSON string literal for `value` — without the quotes.
pub fn json(value: &str, style: JsonStyle) -> String {
    let mut o = String::with_capacity(value.len() + 8);
    for c in value.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            '\u{8}' => o.push_str("\\b"),
            '\u{c}' => o.push_str("\\f"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            '/' if matches!(style, JsonStyle::Slash) => o.push_str("\\/"),
            '<' | '>' | '&' | '\u{2028}' | '\u{2029}' if matches!(style, JsonStyle::HtmlSafe) => {
                o.push_str(&format!("\\u{:04x}", c as u32))
            }
            c if !c.is_ascii() && matches!(style, JsonStyle::Ascii) => {
                let mut buf = [0u16; 2];
                for unit in c.encode_utf16(&mut buf) {
                    o.push_str(&format!("\\u{unit:04x}"));
                }
            }
            c => o.push(c),
        }
    }
    o
}

pub fn hex(bytes: &[u8], upper: bool) -> String {
    let mut o = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        if upper {
            o.push_str(&format!("{b:02X}"));
        } else {
            o.push_str(&format!("{b:02x}"));
        }
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_known_vectors() {
        // RFC 4648 §10.
        assert_eq!(b64(b"foob", B64_STD), "Zm9vYg==");
        assert_eq!(b64(b"foobar", B64_STD), "Zm9vYmFy");
        assert_eq!(b64(b"\xfb\xff", B64_URL), "-_8=");
    }

    #[test]
    fn every_alignment_window_appears_in_a_real_embedding() {
        let v = b"Zq7Xw2mP9vK4tR8sL1nB";
        let w = b64_windows(v, B64_STD);
        assert_eq!(w.len(), 3);
        for (k, prefix) in [(0usize, &b""[..]), (1, b"u"), (2, b"u:")] {
            let mut data = prefix.to_vec();
            data.extend_from_slice(v);
            data.extend_from_slice(b"!tail");
            let enc = b64(&data, B64_STD);
            assert!(enc.contains(&w[k]), "alignment {k} not in {enc}");
        }
    }

    #[test]
    fn short_values_produce_no_short_variants() {
        for (_, s) in spellings("abcdefgh") {
            assert!(s.len() >= MIN_LEN, "variant too short: {s}");
        }
    }

    #[test]
    fn a_plain_token_has_no_url_or_json_variant() {
        let kinds: Vec<Kind> = spellings("abcDEF123456ghi")
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert!(!kinds.contains(&Kind::Url));
        assert!(!kinds.contains(&Kind::Json));
        assert!(kinds.contains(&Kind::Hex));
        assert!(kinds.contains(&Kind::B64));
    }

    #[test]
    fn json_styles_follow_their_encoders() {
        let v = "a/b<c>&d\"é";
        assert_eq!(json(v, JsonStyle::Standard), "a/b<c>&d\\\"é");
        assert_eq!(json(v, JsonStyle::Slash), "a\\/b<c>&d\\\"é");
        assert_eq!(
            json(v, JsonStyle::HtmlSafe),
            "a/b\\u003cc\\u003e\\u0026d\\\"é"
        );
        assert_eq!(json(v, JsonStyle::Ascii), "a/b<c>&d\\\"\\u00e9");
        // serde_json agrees with the standard form.
        let serde = serde_json::to_string(v).unwrap();
        assert_eq!(&serde[1..serde.len() - 1], json(v, JsonStyle::Standard));
    }

    #[test]
    fn base_name_strips_only_known_suffixes() {
        assert_eq!(base_name("radarr-apikey[b64]"), "radarr-apikey");
        assert_eq!(base_name("radarr-apikey[line]"), "radarr-apikey");
        assert_eq!(base_name("radarr-apikey"), "radarr-apikey");
        assert_eq!(base_name("odd[name]"), "odd[name]");
        assert_eq!(Kind::of("x[b64url]"), Kind::B64Url);
    }

    #[test]
    fn lines_takes_key_material_not_headers_or_assignments() {
        let pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nshort1\n-----END PRIVATE KEY-----";
        assert_eq!(lines(pem), vec!["MIIEvQIBADANBgkqhkiG9w0BAQEFAASC"]);
        let tpl =
            "[Interface]\nLOG_LEVEL=information\nurl=http://10.0.20.5:8080/x\nPrivateKey = abc";
        assert!(lines(tpl).is_empty(), "{:?}", lines(tpl));
        assert!(lines("singlelineABC123456789").is_empty());
    }
}
