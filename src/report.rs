//! The one place that turns a hit into text. Nothing else prints a finding.
//!
//! WHY IT IS THE ONLY PLACE: a leak hunter whose own output leaks would be
//! absurd — and that is exactly how a tracker passkey reached a chat log on
//! 2026-09-09, during an exploration that looked harmless. The field was
//! called `trackers` and held an announce URL; nobody was looking for a
//! secret in it.
//!
//! EVERY span of a line is masked ONCE, before any finding is built — the
//! reported hit, a second occurrence, a neighbouring secret, an excepted one,
//! the canary. v0.1.1 masked only the finding's own span, and the sensor
//! wrote the neighbours into the host journal (audit 3, A2-1). Overlapping
//! spans are merged so the tail of a longer secret cannot survive a shorter
//! mask. The sensor prints no line at all ([`format_brief`]); control
//! characters never reach the output ([`sanitize`]).

/// What replaces a secret in any output.
pub const MASK: &str = "<REDACTED>";

/// How much context is kept on either side of a hit.
const CONTEXT: usize = 120;

/// One finding, built only by [`Finding::from_hits`].
///
/// THE LINE IS STORED ALREADY REDACTED — every span of every pattern in it,
/// not only this finding's. In v0.1.1 a finding carried the raw line and
/// only its own span, and `format` masked that one span: the second
/// occurrence of the same value, or a password next to its user name, came
/// out in plaintext (audit 3, A2-1). A `Finding` can no longer hold a raw
/// line: the fields that could are private, and the only constructor masks
/// first.
#[derive(Clone)]
pub struct Finding {
    /// The pattern name — `secret` or `secret[kind]` — never the value.
    pub secret: String,
    pub source: String,
    pub location: String,
    pub timestamp: String,
    /// The text with EVERY hit replaced by [`MASK`].
    line: String,
    /// Where this finding's mask stands in `line`.
    mask: (usize, usize),
}

impl std::fmt::Debug for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Finding")
            .field("secret", &self.secret)
            .field("source", &self.source)
            .field("location", &self.location)
            .field("timestamp", &self.timestamp)
            .field("line", &sanitize(&self.line))
            .field("mask", &self.mask)
            .finish()
    }
}

impl Finding {
    /// Findings for the `hits` in `text`. `all_spans` are the spans of every
    /// pattern found in `text` — the reported hits, excepted ones, the
    /// canary — and all of them are masked before anything is kept. The
    /// hits' own spans are masked too, whether or not the caller passed them
    /// in `all_spans`.
    pub fn from_hits(
        text: &str,
        hits: &[(String, (usize, usize))],
        all_spans: &[(usize, usize)],
        source: &str,
        location: &str,
        timestamp: &str,
    ) -> Vec<Finding> {
        let mut spans = all_spans.to_vec();
        spans.extend(hits.iter().map(|(_, s)| *s));
        let (line, map) = redact_mapped(text, &spans);
        hits.iter()
            .map(|(secret, (start, _))| {
                let mask = map
                    .iter()
                    .find(|((os, oe), _)| os <= start && start < oe)
                    .map(|(_, n)| *n)
                    .unwrap_or((0, 0));
                Finding {
                    secret: secret.clone(),
                    source: source.to_string(),
                    location: location.to_string(),
                    timestamp: timestamp.to_string(),
                    line: line.clone(),
                    mask,
                }
            })
            .collect()
    }

    /// The redacted line.
    pub fn line(&self) -> &str {
        &self.line
    }
}

/// Merge overlapping and touching spans, sorted by start.
fn merge(spans: &[(usize, usize)]) -> Vec<(usize, usize)> {
    let mut spans = spans.to_vec();
    spans.sort_unstable_by_key(|(start, _)| *start);
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for (start, end) in spans {
        if let Some((_, last_end)) = merged.last_mut()
            && start <= *last_end
        {
            // Overlapping or touching: extend the last span.
            *last_end = (*last_end).max(end);
            continue;
        }
        merged.push((start, end));
    }
    merged
}

/// A merged span in the original text and the span of its mask in the output.
type Moved = ((usize, usize), (usize, usize));

/// Replace every span with [`MASK`] and say where each merged span went.
fn redact_mapped(line: &str, spans: &[(usize, usize)]) -> (String, Vec<Moved>) {
    let mut out = String::with_capacity(line.len());
    let mut map = Vec::new();
    let mut cursor = 0;
    for (start, end) in merge(spans) {
        let start = start.min(line.len()).max(cursor);
        let end = end.min(line.len());
        out.push_str(&line[cursor..start]);
        let at = out.len();
        out.push_str(MASK);
        map.push(((start, end), (at, out.len())));
        cursor = end.max(start);
    }
    out.push_str(&line[cursor..]);
    (out, map)
}

/// Replace every span with [`MASK`].
///
/// Overlapping spans are merged before replacement, so the tail of a longer
/// secret cannot survive a shorter one's mask.
pub fn redact(line: &str, spans: &[(usize, usize)]) -> String {
    redact_mapped(line, spans).0
}

/// Control characters out of text meant for a terminal, a journal or a mail:
/// an escape sequence in a log line (OSC 52 writes the clipboard, `ESC[2J`
/// clears the screen) must not reach whoever reads the report. Tab stays.
pub fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_control() && c != '\t' {
                '\u{fffd}'
            } else {
                c
            }
        })
        .collect()
}

/// Render a finding with context — for `scan`, read by a person. The value
/// cannot appear: the line was redacted when the finding was built, before
/// it is ever trimmed or printed.
pub fn format(f: &Finding) -> String {
    let redacted = &f.line;
    let (hit, hit_end) = f.mask;
    let from = floor_char_boundary(redacted, hit.saturating_sub(CONTEXT));
    let to = floor_char_boundary(redacted, (hit_end + CONTEXT).min(redacted.len()));
    let mut context = String::new();
    if from > 0 {
        context.push('…');
    }
    context.push_str(&sanitize(&redacted[from..to]));
    if to < redacted.len() {
        context.push('…');
    }
    format!(
        "{}  {}  {}  {}\n  {}\n  → just rotor-leser {}",
        sanitize(&f.secret),
        f.source,
        sanitize(&f.location),
        f.timestamp,
        context,
        crate::variants::base_name(&f.secret)
    )
}

/// Render a finding WITHOUT any line content — for `sensor`, whose stdout
/// lands in the host journal and from there in Loki and every chat log that
/// quotes it. A redacted line is still a copy of someone else's log line,
/// and the redaction is the one thing that must never fail there. Name,
/// source, location and time are enough to start the triage on the machine.
pub fn format_brief(f: &Finding) -> String {
    format!(
        "{}  {}  {}  {}\n  → just rotor-leser {}",
        sanitize(&f.secret),
        f.source,
        sanitize(&f.location),
        f.timestamp,
        crate::variants::base_name(&f.secret)
    )
}

fn floor_char_boundary(s: &str, mut i: usize) -> usize {
    i = i.min(s.len());
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANARY: &str = "sk-canary-9f3b2a7e4d1c";

    fn finding(line: &str, span: (usize, usize)) -> Finding {
        Finding::from_hits(
            line,
            &[("test-secret".to_string(), span)],
            &[],
            "journal",
            "server/media-01 radarr.service",
            "2026-09-18 14:03:22",
        )
        .remove(0)
    }

    #[test]
    fn redact_replaces_the_span() {
        let line = format!("curl -H 'X-Api-Key: {CANARY}' http://x/");
        let start = line.find(CANARY).unwrap();
        let out = redact(&line, &[(start, start + CANARY.len())]);
        assert_eq!(out, "curl -H 'X-Api-Key: <REDACTED>' http://x/");
    }

    #[test]
    fn formatted_output_never_contains_the_value() {
        let line = format!("curl -H 'X-Api-Key: {CANARY}' http://x/");
        let start = line.find(CANARY).unwrap();
        let out = format(&finding(&line, (start, start + CANARY.len())));
        assert!(!out.contains(CANARY), "value appears in output: {out}");
    }

    #[test]
    fn formatted_output_names_secret_location_and_rotor() {
        let line = format!("x {CANARY} y");
        let start = line.find(CANARY).unwrap();
        let out = format(&finding(&line, (start, start + CANARY.len())));
        assert!(out.contains("test-secret"));
        assert!(out.contains("radarr.service"));
        assert!(out.contains("just rotor-leser test-secret"));
    }

    #[test]
    fn redact_handles_several_spans_in_one_line() {
        let line = format!("{CANARY} middle {CANARY}");
        let a = (0, CANARY.len());
        let b = (line.rfind(CANARY).unwrap(), line.len());
        let out = redact(&line, &[a, b]);
        assert_eq!(out, "<REDACTED> middle <REDACTED>");
        assert!(!out.contains(CANARY));
    }

    #[test]
    fn redact_keeps_multibyte_context_intact() {
        let line = format!("Schlüssel läuft: {CANARY} — Ende");
        let start = line.find(CANARY).unwrap();
        let out = redact(&line, &[(start, start + CANARY.len())]);
        assert_eq!(out, "Schlüssel läuft: <REDACTED> — Ende");
    }

    #[test]
    fn long_lines_are_trimmed_around_the_hit_without_leaking() {
        let filler = "x".repeat(500);
        let line = format!("{filler}{CANARY}{filler}");
        let start = filler.len();
        let out = format(&finding(&line, (start, start + CANARY.len())));
        assert!(!out.contains(CANARY));
        assert!(out.len() < 400, "context not trimmed: {} chars", out.len());
    }

    #[test]
    fn redact_merges_overlapping_spans_without_leaking_a_tail() {
        let line = format!("head {CANARY} tail");
        let start = line.find(CANARY).unwrap();
        let end = start + CANARY.len();
        // Two spans over the same secret with different boundaries.
        let out = redact(&line, &[(start, end), (start + 4, end)]);
        assert_eq!(out, "head <REDACTED> tail");
        assert!(
            !out.contains(&CANARY[4..]),
            "tail of the secret survived: {out}"
        );
    }

    #[test]
    fn redact_merges_touching_spans() {
        let line = "aaaabbbb".to_string();
        let out = redact(&line, &[(0, 4), (4, 8)]);
        assert_eq!(out, "<REDACTED>");
    }

    #[test]
    fn debug_output_never_contains_the_value() {
        let line = format!("x {CANARY} y");
        let start = line.find(CANARY).unwrap();
        let f = finding(&line, (start, start + CANARY.len()));
        let shown = format!("{f:?}");
        assert!(!shown.contains(CANARY), "Debug leaks the value: {shown}");
    }
}
