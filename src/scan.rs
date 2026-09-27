//! The matcher: Aho-Corasick over the plaintext values, streamed line by line
//! with an overlapping window.
//!
//! WHY PLAINTEXT AND NOT HMAC over tokens: a tokenizer has to guess where a
//! secret starts and ends, and that guess is what the five chat leaks and the
//! two mask gaps were made of. Aho-Corasick needs no boundaries.

use crate::variants::{self, Kind};
use aho_corasick::AhoCorasick;
use anyhow::{Context, Result};
use std::io::BufRead;
use zeroize::Zeroize;

pub use crate::variants::MIN_LEN;

/// One hit: the pattern name (`secret` or `secret[kind]`) and its byte span.
pub type Hit = (String, (usize, usize));

pub struct Scanner {
    ac: AhoCorasick,
    names: Vec<String>,
    longest: usize,
    searched: usize,
}

impl Scanner {
    pub fn new(secrets: Vec<(String, String)>) -> Result<Scanner> {
        let mut names: Vec<String> = Vec::new();
        let mut values: Vec<String> = Vec::new();
        let mut searched = 0usize;
        for (name, mut raw) in secrets {
            // Trim once: use the trimmed value for both the length check and
            // the pattern. A secret read from a file normally carries a
            // trailing newline; that newline must not go into the pattern, or
            // it can never match anything — BufRead::lines() strips line
            // terminators from every scanned line. Spaces INSIDE the value are
            // preserved.
            let v = raw.trim().to_string();
            raw.zeroize();
            // Values shorter than MIN_LEN are not searched for — in no
            // spelling: they would match constantly and drown every real
            // finding. The run reports how many were skipped.
            if v.len() < MIN_LEN {
                let mut v = v;
                v.zeroize();
                continue;
            }
            searched += 1;
            let first = values.len();
            for (kind, s) in variants::spellings(&v) {
                names.push(kind.name(&name));
                values.push(s);
            }
            for l in variants::lines(&v) {
                if values[first..].contains(&l) {
                    continue;
                }
                names.push(Kind::Line.name(&name));
                values.push(l);
            }
            names.push(name);
            values.push(v);
        }
        let longest = values.iter().map(|v| v.len()).max().unwrap_or(0);
        let ac = AhoCorasick::new(&values).context("building the automaton");
        // The automaton holds its own copy; ours need not outlive it. (The
        // copy inside the automaton cannot be wiped — see README, "Memory".)
        for v in &mut values {
            v.zeroize();
        }
        Ok(Scanner {
            ac: ac?,
            names,
            longest,
            searched,
        })
    }

    pub fn longest(&self) -> usize {
        self.longest
    }

    /// Every hit in `line`, OVERLAPPING ones included. A secret that contains
    /// another (a rendered URL holding a password) must yield both spans, or
    /// redaction masks only the inner one.
    pub fn scan_line(&self, line: &str) -> Vec<Hit> {
        self.ac
            .find_overlapping_iter(line)
            .map(|m| {
                (
                    self.names[m.pattern().as_usize()].clone(),
                    (m.start(), m.end()),
                )
            })
            .collect()
    }

    /// Scan a stream line by line, carrying the tail of the previous line so a
    /// value broken across a line boundary is still found. One callback per
    /// hit — see [`Scanner::scan_stream_grouped`] for the form a report needs.
    ///
    /// Returns the number of lines read — a caller that gets 0 read nothing,
    /// which is a tool error, not a clean result.
    #[allow(clippy::type_complexity)]
    pub fn scan_stream<R: BufRead>(
        &self,
        r: R,
        on_hit: &mut dyn FnMut(&str, &str, (usize, usize)),
    ) -> Result<u64> {
        self.scan_stream_grouped(r, &mut |text, hits, _all| {
            for (name, span) in hits {
                on_hit(name, text, *span);
            }
        })
    }

    /// Like [`Scanner::scan_stream`], but one callback per TEXT: the text, the
    /// hits to report in it, and EVERY span of every pattern in it.
    ///
    /// WHY THE THIRD ARGUMENT: a report shows context around a hit, and that
    /// context must have every other secret in the same text masked too —
    /// the second occurrence of the same value, the password next to the
    /// user name, an excepted identifier, the canary. Masking only the
    /// reported hit is how v0.1.1 printed the neighbours in plaintext into
    /// the host journal (audit 3, A2-1).
    ///
    /// The callback runs only for texts with at least one hit to report.
    #[allow(clippy::type_complexity)]
    pub fn scan_stream_grouped<R: BufRead>(
        &self,
        r: R,
        on_text: &mut dyn FnMut(&str, &[Hit], &[(usize, usize)]),
    ) -> Result<u64> {
        let mut carry = String::new();
        let mut lines = 0u64;
        for line in r.lines() {
            let line = line.context("reading a line")?;
            lines += 1;

            let seam = carry.len();
            let joined = if carry.is_empty() {
                line.clone()
            } else {
                format!("{carry}{line}")
            };

            // Only hits that actually CROSS the seam come from the window;
            // hits sitting entirely in the new line are reported by the plain
            // scan below, and hits entirely inside `carry` were reported when
            // that text was the current line. Otherwise every hit near a line
            // end is counted twice.
            if seam > 0 {
                let all = self.scan_line(&joined);
                let crossing: Vec<Hit> = all
                    .iter()
                    .filter(|(_, (start, end))| *start < seam && *end > seam)
                    .cloned()
                    .collect();
                if !crossing.is_empty() {
                    let spans: Vec<(usize, usize)> = all.iter().map(|(_, s)| *s).collect();
                    on_text(&joined, &crossing, &spans);
                }
            }

            let hits = self.scan_line(&line);
            if !hits.is_empty() {
                let spans: Vec<(usize, usize)> = hits.iter().map(|(_, s)| *s).collect();
                on_text(&line, &hits, &spans);
            }

            // Carry the tail of the JOINED text, not of this line alone —
            // otherwise a secret spanning three lines loses its head.
            let tail = joined.len().saturating_sub(self.longest);
            let tail = floor_char_boundary(&joined, tail);
            carry = joined[tail..].to_string();
        }
        Ok(lines)
    }

    /// How many SECRETS the automaton actually searches for — `Scanner::new`
    /// drops everything shorter than `MIN_LEN`, and a run has to be able to
    /// say so. Encoded variants are not counted here, see
    /// [`Scanner::variant_count`].
    pub fn pattern_count(&self) -> usize {
        self.searched
    }

    /// How many patterns beyond the plain values: encoded spellings and
    /// single lines of multi-line values.
    pub fn variant_count(&self) -> usize {
        self.names.len() - self.searched
    }

    /// Which kinds of spelling the automaton carries for `secret`.
    pub fn kinds_of(&self, secret: &str) -> Vec<Kind> {
        let mut out: Vec<Kind> = Vec::new();
        for n in &self.names {
            if variants::base_name(n) == secret {
                let k = Kind::of(n);
                if !out.contains(&k) {
                    out.push(k);
                }
            }
        }
        out
    }
}

fn floor_char_boundary(s: &str, mut i: usize) -> usize {
    while i < s.len() && !s.is_char_boundary(i) {
        i -= 1;
    }
    i.min(s.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scanner() -> Scanner {
        Scanner::new(vec![
            ("radarr-apikey".into(), "abc123def456ghi789".into()),
            ("kurz".into(), "pw42".into()),
        ])
        .unwrap()
    }

    #[test]
    fn finds_a_value_in_the_middle_of_a_string() {
        let hits = scanner().scan_line("curl -H 'X-Api-Key: abc123def456ghi789' http://x/");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0, "radarr-apikey");
    }

    #[test]
    fn finds_a_value_with_no_delimiters_around_it() {
        // No whitespace, no boundary: exactly where a tokenizer would fail.
        let hits = scanner().scan_line("xxxabc123def456ghi789yyy");
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn reports_no_hit_for_a_clean_line() {
        assert!(scanner().scan_line("nothing to see here").is_empty());
    }

    #[test]
    fn finds_a_value_broken_across_a_line_boundary() {
        let data = "prefix abc123def\n456ghi789 suffix\n";
        let mut found = Vec::new();
        let n = scanner()
            .scan_stream(data.as_bytes(), &mut |name, _line, _span| {
                found.push(name.to_string())
            })
            .unwrap();
        assert_eq!(n, 2, "two lines read");
        assert_eq!(
            found,
            vec!["radarr-apikey"],
            "found across the line boundary"
        );
    }

    #[test]
    fn a_hit_inside_one_line_is_not_reported_twice_by_the_window() {
        let data = "a abc123def456ghi789 b\nc d\n";
        let mut found = Vec::new();
        scanner()
            .scan_stream(data.as_bytes(), &mut |name, _l, _s| {
                found.push(name.to_string())
            })
            .unwrap();
        assert_eq!(found.len(), 1, "Fenster meldet doppelt: {found:?}");
    }

    #[test]
    fn longest_is_the_longest_pattern() {
        // The hex spelling doubles the value and is the longest pattern; the
        // carry must cover it or a hex dump broken across lines is lost.
        assert_eq!(scanner().longest(), 2 * "abc123def456ghi789".len());
    }

    #[test]
    fn empty_and_whitespace_secrets_are_refused() {
        // An empty value would match every line; a value of only whitespace would match almost every line.
        let s = Scanner::new(vec![("leer".into(), String::new())]).unwrap();
        assert!(s.scan_line("irgendwas").is_empty());
    }

    #[test]
    fn pattern_count_excludes_the_too_short_values() {
        // "pw42" is 4 bytes, below MIN_LEN — it must not be counted.
        let s = scanner();
        assert_eq!(s.pattern_count(), 1);
    }

    #[test]
    fn finds_a_value_split_across_three_lines() {
        // Middle line shorter than the longest secret: the carry must keep
        // context from before it, or this hit vanishes silently.
        let data = "prefix abc123\ndef456\nghi789 suffix\n";
        let mut found = Vec::new();
        scanner()
            .scan_stream(data.as_bytes(), &mut |name, _l, _s| {
                found.push(name.to_string())
            })
            .unwrap();
        assert_eq!(found, vec!["radarr-apikey"], "lost across three lines");
    }

    #[test]
    fn a_value_with_a_trailing_newline_is_still_findable() {
        // The normal shape of a secret read from a file.
        let s = Scanner::new(vec![("k".into(), "abc123def456ghi789\n".into())]).unwrap();
        assert_eq!(s.scan_line("x abc123def456ghi789 y").len(), 1);
    }

    #[test]
    fn spaces_inside_a_value_are_preserved() {
        let s = Scanner::new(vec![("pw".into(), "  pass word here  ".into())]).unwrap();
        assert_eq!(s.scan_line("login=pass word here;").len(), 1);
        assert_eq!(s.scan_line("login=passwordhere;").len(), 0);
    }
}
