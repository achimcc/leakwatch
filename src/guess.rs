//! Secret-looking values leakwatch does NOT know — found by context, never
//! by shape alone. A bare run of hex is a commit, a machine id, an image
//! digest; a bare run of Base64-ish characters is every long path. Guessing
//! on those would turn a deploy diagnosis into `<REDACTED?>`. So only:
//! a header, an assignment to a key-like word, the user-info of a URL, a
//! query parameter, and the JWT format.

use std::sync::LazyLock;

use regex::Regex;

/// (pattern, capture group that is the value, kind)
static PATTERNS: LazyLock<Vec<(Regex, usize, &'static str)>> = LazyLock::new(|| {
    vec![
        (
            Regex::new(r"(?i)authorization:\s*(?:bearer|basic)\s+(\S+)").unwrap(),
            1,
            "header",
        ),
        (
            Regex::new(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
                .unwrap(),
            0,
            "jwt",
        ),
        (
            Regex::new(r"https?://[^/\s:@]+:([^@\s]+)@").unwrap(),
            1,
            "url",
        ),
        (
            Regex::new(
                r#"(?i)[?&](?:api_?key|apikey|token|access_token|key|password|passkey|secret)=([^&\s"'<>]+)"#,
            )
            .unwrap(),
            1,
            "query",
        ),
        (
            Regex::new(
                r#"(?i)\b(?:x-api-key|x-auth-token|apikey|api_key|api-key|token|access_token|refresh_token|password|passwd|secret|client_secret|private_?key|preshared_?key)["']?\s*[:=]\s*["']?([^\s"'&;,]+)"#,
            )
            .unwrap(),
            1,
            "header",
        ),
    ]
});

/// Byte spans of values that look like secrets, with the kind of context
/// they were found in. Non-overlapping, sorted by start; where two patterns
/// claim the same bytes the earlier (more specific) pattern wins — the
/// generic `key=value` assignment comes last.
pub fn spans(line: &str) -> Vec<((usize, usize), &'static str)> {
    let mut out: Vec<((usize, usize), &'static str)> = Vec::new();
    for (re, group, kind) in PATTERNS.iter() {
        for c in re.captures_iter(line) {
            let Some(m) = c.get(*group) else { continue };
            let (s, e) = (m.start(), m.end());
            if s == e {
                continue;
            }
            if out.iter().any(|((os, oe), _)| s < *oe && *os < e) {
                continue;
            }
            out.push(((s, e), kind));
        }
    }
    out.sort_by_key(|((s, _), _)| *s);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(line: &str) -> Vec<(&'static str, &str)> {
        spans(line)
            .into_iter()
            .map(|((s, e), k)| (k, &line[s..e]))
            .collect()
    }

    #[test]
    fn header_bearer_and_api_key() {
        assert_eq!(
            kinds("GET / Authorization: Bearer abc.def-123 X-Api-Key: k9f8e7 end"),
            vec![("header", "abc.def-123"), ("header", "k9f8e7")]
        );
    }

    #[test]
    fn assignment_forms() {
        assert_eq!(kinds("password=hunter2 ok"), vec![("header", "hunter2")]);
        assert_eq!(kinds("TOKEN: tok_123 ok"), vec![("header", "tok_123")]);
        assert_eq!(
            kinds(r#"{"client_secret": "s3cr3t", "x": 1}"#),
            vec![("header", "s3cr3t")]
        );
    }

    #[test]
    fn wireguard_keys_by_name() {
        assert_eq!(
            kinds("PrivateKey = abcDEF0123456789+/abcDEF0123456789+/abcDEF0= ok"),
            vec![("header", "abcDEF0123456789+/abcDEF0123456789+/abcDEF0=")]
        );
        assert_eq!(kinds("PresharedKey=xyz"), vec![("header", "xyz")]);
    }

    #[test]
    fn jwt_whole() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        assert_eq!(kinds(&format!("auth {jwt} done")), vec![("jwt", jwt)]);
    }

    #[test]
    fn url_userinfo_only_password() {
        assert_eq!(
            kinds("dial https://user:pw-9x@db.example.org:5432/x"),
            vec![("url", "pw-9x")]
        );
    }

    #[test]
    fn query_values() {
        assert_eq!(
            kinds("GET /api?apikey=abc123&x=1&passkey=zzz HTTP/1.1"),
            vec![("query", "abc123"), ("query", "zzz")]
        );
    }

    #[test]
    fn store_paths_shas_digests_untouched() {
        let line = "/nix/store/ar1ymfy01cg8vpp8y388zz37lvln1lsi-gestalt-0.3.1/bin/gestalt \
                    commit 4d5972112acad83345cfbc7466821c932398dbe7 \
                    sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 \
                    id=3b241101-e2bb-4255-8caf-4136c566a962 \
                    /var/lib/private/jellyfin/plugins/configurations/Jellyfin.Plugin.Something.xml";
        assert!(spans(line).is_empty(), "{:?}", kinds(line));
    }

    #[test]
    fn spans_do_not_overlap_and_are_sorted() {
        let s = spans(
            "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c token=abc",
        );
        for w in s.windows(2) {
            assert!(w[0].0.1 <= w[1].0.0, "{s:?}");
        }
        assert!(!s.is_empty());
    }
}
