//! The one place that turns a hit into text. Nothing else prints a finding.
//!
//! WHY IT IS THE ONLY PLACE: a leak hunter whose own output leaks would be
//! absurd — and that is exactly how the TNTracker passkey reached the chat on
//! 2026-09-09, during an exploration that looked harmless.

/// What replaces a secret in any output.
pub const MASK: &str = "<TREFFER>";

/// How much context is kept on either side of a hit.
const CONTEXT: usize = 120;

#[derive(Debug, Clone)]
pub struct Finding {
    /// The sops key name — never the value.
    pub secret: String,
    pub source: String,
    pub location: String,
    pub timestamp: String,
    pub line: String,
    pub span: (usize, usize),
}

/// Replace every span with [`MASK`].
///
/// Spans are byte offsets into `line` and must not overlap. They are applied
/// back to front so earlier offsets stay valid.
pub fn redact(line: &str, spans: &[(usize, usize)]) -> String {
    let mut out = line.to_string();
    let mut spans = spans.to_vec();
    spans.sort_unstable_by_key(|(start, _)| std::cmp::Reverse(*start));
    for (start, end) in spans {
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
        assert_eq!(out, "curl -H 'X-Api-Key: <TREFFER>' http://x/");
    }

    #[test]
    fn formatted_output_never_contains_the_value() {
        let line = format!("curl -H 'X-Api-Key: {CANARY}' http://x/");
        let start = line.find(CANARY).unwrap();
        let out = format(&finding(&line, (start, start + CANARY.len())));
        assert!(
            !out.contains(CANARY),
            "der Wert steht in der Ausgabe: {out}"
        );
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
        assert_eq!(out, "<TREFFER> middle <TREFFER>");
        assert!(!out.contains(CANARY));
    }

    #[test]
    fn redact_keeps_multibyte_context_intact() {
        let line = format!("Schlüssel läuft: {CANARY} — Ende");
        let start = line.find(CANARY).unwrap();
        let out = redact(&line, &[(start, start + CANARY.len())]);
        assert_eq!(out, "Schlüssel läuft: <TREFFER> — Ende");
    }

    #[test]
    fn long_lines_are_trimmed_around_the_hit_without_leaking() {
        let filler = "x".repeat(500);
        let line = format!("{filler}{CANARY}{filler}");
        let start = filler.len();
        let out = format(&finding(&line, (start, start + CANARY.len())));
        assert!(!out.contains(CANARY));
        assert!(
            out.len() < 400,
            "Kontext nicht gekürzt: {} Zeichen",
            out.len()
        );
    }
}
