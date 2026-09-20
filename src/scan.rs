//! The matcher: Aho-Corasick over the plaintext values, streamed line by line
//! with an overlapping window.
//!
//! WHY PLAINTEXT AND NOT HMAC over tokens: a tokenizer has to guess where a
//! secret starts and ends, and that guess is what the five chat leaks and the
//! two mask gaps were made of. Aho-Corasick needs no boundaries.

use aho_corasick::AhoCorasick;
use anyhow::{Context, Result};
use std::io::BufRead;

pub struct Scanner {
    ac: AhoCorasick,
    names: Vec<String>,
    longest: usize,
}

/// Values shorter than this are not searched for: they would match constantly
/// and drown every real finding. The audit reports how many were skipped.
const MIN_LEN: usize = 8;

impl Scanner {
    pub fn new(secrets: Vec<(String, String)>) -> Result<Scanner> {
        // Trim once: use the trimmed value for both the length check and the
        // pattern. A secret read from a file normally carries a trailing
        // newline; that newline must not go into the pattern, or it can never
        // match anything — BufRead::lines() strips line terminators from every
        // scanned line. Spaces INSIDE the value are preserved.
        let usable: Vec<(String, String)> = secrets
            .into_iter()
            .map(|(n, v)| (n, v.trim().to_string()))
            .filter(|(_, v)| v.len() >= MIN_LEN)
            .collect();
        let names: Vec<String> = usable.iter().map(|(n, _)| n.clone()).collect();
        let values: Vec<String> = usable.into_iter().map(|(_, v)| v).collect();
        let longest = values.iter().map(|v| v.len()).max().unwrap_or(0);
        let ac = AhoCorasick::new(&values).context("building the automaton")?;
        Ok(Scanner { ac, names, longest })
    }

    pub fn longest(&self) -> usize {
        self.longest
    }

    pub fn scan_line(&self, line: &str) -> Vec<(String, (usize, usize))> {
        self.ac
            .find_iter(line)
            .map(|m| {
                (
                    self.names[m.pattern().as_usize()].clone(),
                    (m.start(), m.end()),
                )
            })
            .collect()
    }

    /// Scan a stream line by line, carrying the tail of the previous line so a
    /// value broken across a line boundary is still found.
    ///
    /// Returns the number of lines read — a caller that gets 0 read nothing,
    /// which is a tool error, not a clean result.
    #[allow(clippy::type_complexity)]
    pub fn scan_stream<R: BufRead>(
        &self,
        r: R,
        on_hit: &mut dyn FnMut(&str, &str, (usize, usize)),
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
                for (name, (start, end)) in self.scan_line(&joined) {
                    if start < seam && end > seam {
                        on_hit(&name, &joined, (start, end));
                    }
                }
            }

            for (name, span) in self.scan_line(&line) {
                on_hit(&name, &line, span);
            }

            // Carry the tail of the JOINED text, not of this line alone —
            // otherwise a secret spanning three lines loses its head.
            let tail = joined.len().saturating_sub(self.longest);
            let tail = floor_char_boundary(&joined, tail);
            carry = joined[tail..].to_string();
        }
        Ok(lines)
    }

    /// How many values the automaton actually searches for — `Scanner::new`
    /// drops everything shorter than `MIN_LEN`, and a run has to be able to
    /// say so.
    pub fn pattern_count(&self) -> usize {
        self.names.len()
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
    fn longest_is_the_longest_secret() {
        assert_eq!(scanner().longest(), "abc123def456ghi789".len());
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
