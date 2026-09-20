//! Counts what a scan found and covered, for export to a metrics endpoint.
//!
//! The textfile metric for the sensor — the house pattern (gast-speicher,
//! dns-abgleich, sicherung, groundtruth): timer, oneshot, written atomically.

/// Escape a label value per the Prometheus text exposition format:
/// backslash, double quote and newline each need an escape, or a value
/// carrying one of them corrupts the line — and node-exporter's textfile
/// collector then rejects the WHOLE file, not just this metric.
fn escape_label(v: &str) -> String {
    v.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

pub fn render(hits: &[(String, String, u64)], canaries: &[(String, bool)], now: u64) -> String {
    let mut out = String::new();
    out.push_str("# HELP leakwatch_finding secrets in places they should not be\n");
    out.push_str("# TYPE leakwatch_finding gauge\n");
    for (secret, source, n) in hits {
        let secret = escape_label(secret);
        let source = escape_label(source);
        out.push_str(&format!(
            "leakwatch_finding{{secret=\"{secret}\",source=\"{source}\"}} {n}\n"
        ));
    }
    // ONE LINE PER SOURCE NAME, FOLDED WITH AND — NOT ONE PER SOURCE.
    //
    // A run can hold several sources of the SAME name: one `journal` per
    // guest. Rendering a line each produced repeated label sets, and a
    // repeated label set is not a metric — `promtool check metrics` calls it
    // "not unique", and a Prometheus client registry drops every line after
    // the first. Measured on a real installation on 2026-09-20: 33 identical
    // `leakwatch_canary_found{source="journal"}` lines, of which exactly one
    // survived the scrape, while node-exporter logged
    // `was collected before with the same name and label values` on every
    // scrape. The neighbouring textfile metrics were unharmed, so nothing
    // turned red — the positive control simply stopped meaning what it says.
    //
    // FOLDED WITH AND, because that is what the question deserves: "did the
    // journal adapter work?" is false as soon as ONE of its sources failed.
    // Taking the first (what the registry did by accident) or the maximum
    // would let a healthy guest cover a broken one — the exact failure the
    // per-adapter check exists to prevent.
    //
    // The GUEST is not lost: it rides in the error line and in `location`,
    // where it can be read without multiplying label sets — and where it does
    // not break the exception lists and alert rules that key on `source`.
    out.push_str("# HELP leakwatch_canary_found did the run find anything at all?\n");
    out.push_str("# TYPE leakwatch_canary_found gauge\n");
    let mut gefaltet: Vec<(String, bool)> = Vec::new();
    for (source, ok) in canaries {
        match gefaltet.iter_mut().find(|(s, _)| s == source) {
            Some((_, vorher)) => *vorher = *vorher && *ok,
            None => gefaltet.push((source.clone(), *ok)),
        }
    }
    for (source, ok) in &gefaltet {
        let source = escape_label(source);
        out.push_str(&format!(
            "leakwatch_canary_found{{source=\"{source}\"}} {}\n",
            u8::from(*ok)
        ));
    }
    out.push_str(&format!("leakwatch_run_timestamp {now}\n"));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_never_contain_a_value() {
        let text = render(
            &[("radarr-apikey".into(), "journal".into(), 3)],
            &[("journal".into(), true)],
            1758300000,
        );
        assert!(text.contains("leakwatch_finding"));
        assert!(text.contains("radarr-apikey"));
        assert!(!text.contains("abc123"));
    }

    #[test]
    fn a_failed_canary_is_zero_not_absent() {
        let text = render(&[], &[("loki".into(), false)], 1758300000);
        assert!(text.contains("leakwatch_canary_found{source=\"loki\"} 0"));
    }

    #[test]
    fn repeated_source_names_render_exactly_one_line() {
        // The sensor case: one `journal` source per guest.
        let canaries: Vec<(String, bool)> = (0..33)
            .map(|_| ("journal".to_string(), true))
            .chain(std::iter::once(("loki".to_string(), true)))
            .collect();
        let text = render(&[], &canaries, 1758300000);
        let journal_lines = text
            .lines()
            .filter(|l| l.starts_with("leakwatch_canary_found{source=\"journal\"}"))
            .count();
        assert_eq!(
            journal_lines, 1,
            "a repeated label set is not a metric — promtool calls it \"not unique\" \
             and a registry drops every line after the first:\n{text}"
        );
        assert!(text.contains("leakwatch_canary_found{source=\"loki\"} 1"));
    }

    #[test]
    fn one_failed_source_makes_the_whole_adapter_zero() {
        // 32 healthy guests must not cover the one that delivered nothing.
        let mut canaries: Vec<(String, bool)> =
            (0..32).map(|_| ("journal".to_string(), true)).collect();
        canaries.push(("journal".to_string(), false));
        let text = render(&[], &canaries, 1758300000);
        assert!(
            text.contains("leakwatch_canary_found{source=\"journal\"} 0"),
            "folding must be AND, not first-wins or max:\n{text}"
        );
    }

    #[test]
    fn the_order_of_a_failure_among_its_peers_does_not_matter() {
        // Same set, failure first instead of last.
        let mut canaries: Vec<(String, bool)> = vec![("journal".to_string(), false)];
        canaries.extend((0..32).map(|_| ("journal".to_string(), true)));
        let text = render(&[], &canaries, 1758300000);
        assert!(
            text.contains("leakwatch_canary_found{source=\"journal\"} 0"),
            "a failure seen first must survive the healthy ones after it:\n{text}"
        );
    }

    #[test]
    fn a_label_value_with_quotes_backslashes_and_a_newline_stays_one_line() {
        let nasty = "weird\"name\\with\nnewline".to_string();
        let text = render(&[(nasty, "journal".into(), 1)], &[], 1758300000);
        let finding_line = text
            .lines()
            .find(|l| l.starts_with("leakwatch_finding{"))
            .expect("no leakwatch_finding line rendered");
        // The escaped newline must not have split the metric onto a second line.
        assert!(
            finding_line.contains("\\n"),
            "newline not escaped: {finding_line}"
        );
        assert!(
            finding_line.contains("\\\""),
            "quote not escaped: {finding_line}"
        );
        assert!(
            finding_line.contains("\\\\"),
            "backslash not escaped: {finding_line}"
        );
        // Quoting stays balanced: exactly two UNESCAPED double quotes bound each
        // label value (secret="..." and source="...").
        let unescaped_quotes = finding_line
            .char_indices()
            .filter(|&(i, c)| c == '"' && !finding_line.as_bytes()[..i].ends_with(b"\\"))
            .count();
        assert_eq!(unescaped_quotes, 4, "quoting not balanced: {finding_line}");
    }
}
