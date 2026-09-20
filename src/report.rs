//! The one place that turns a hit into text. Nothing else prints a finding.
//!
//! WHY IT IS THE ONLY PLACE: a leak hunter whose own output leaks would be
//! absurd — and that is exactly how the TNTracker passkey reached the chat on
//! 2026-09-09, during an exploration that looked harmless.
//!
//! Overlapping spans are merged before redacting to prevent the tail of a secret from
//! surviving when a shorter mask replaces a longer secret. Debug is hand-written to
//! redact the line field and prevent accidental leaks from `{:?}` or `dbg!` calls.

/// What replaces a secret in any output.
pub const MASK: &str = "<REDACTED>";

/// How much context is kept on either side of a hit.
const CONTEXT: usize = 120;

#[derive(Clone)]
pub struct Finding {
    /// The sops key name — never the value.
    pub secret: String,
    pub source: String,
    pub location: String,
    pub timestamp: String,
    pub line: String,
    pub span: (usize, usize),
}

impl std::fmt::Debug for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Finding")
            .field("secret", &self.secret)
            .field("source", &self.source)
            .field("location", &self.location)
            .field("timestamp", &self.timestamp)
            .field("line", &redact(&self.line, &[self.span]))
            .field("span", &self.span)
            .finish()
    }
}

/// Replace every span with [`MASK`].
///
/// Overlapping spans are merged before replacement. The merged spans are applied
/// back to front so earlier offsets stay valid.
pub fn redact(line: &str, spans: &[(usize, usize)]) -> String {
    let mut out = line.to_string();
    let mut spans = spans.to_vec();

    // Merge overlapping and touching spans.
    spans.sort_unstable_by_key(|(start, _)| *start);
    let mut merged = Vec::new();
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

    // Apply replacements back to front.
    merged.sort_unstable_by_key(|(start, _)| std::cmp::Reverse(*start));
    for (start, end) in merged {
        out.replace_range(start..end, MASK);
    }
    out
}

/// Render a finding. The value cannot appear: the line is redacted before it
/// is ever trimmed or printed.
pub fn format(f: &Finding) -> String {
    let redacted = redact(&f.line, &[f.span]);
    // Trim AFTER redacting — trimming first could cut the span and let the
    // tail of a secret survive.
    let hit = redacted.find(MASK).unwrap_or(0);
    let from = hit.saturating_sub(CONTEXT);
    let to = (hit + MASK.len() + CONTEXT).min(redacted.len());
    let from = floor_char_boundary(&redacted, from);
    let to = floor_char_boundary(&redacted, to);
    let mut context = String::new();
    if from > 0 {
        context.push('…');
    }
    context.push_str(&redacted[from..to]);
    if to < redacted.len() {
        context.push('…');
    }
    format!(
        "{}  {}  {}  {}\n  {}\n  → just rotor-leser {}",
        f.secret, f.source, f.location, f.timestamp, context, f.secret
    )
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

    const CANARY: &str = "sk-canary-9f3b2a7e4d1c";

    fn finding(line: &str, span: (usize, usize)) -> Finding {
        Finding {
            secret: "test-secret".into(),
            source: "journal".into(),
            location: "server/media-01 radarr.service".into(),
            timestamp: "2026-09-18 14:03:22".into(),
            line: line.into(),
            span,
        }
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
