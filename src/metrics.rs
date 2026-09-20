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
    out.push_str("# HELP leakwatch_treffer Geheimnisse an Stellen, an die sie nicht gehoeren\n");
    out.push_str("# TYPE leakwatch_treffer gauge\n");
    for (secret, source, n) in hits {
        let secret = escape_label(secret);
        let source = escape_label(source);
        out.push_str(&format!(
            "leakwatch_treffer{{secret=\"{secret}\",quelle=\"{source}\"}} {n}\n"
        ));
    }
    out.push_str("# HELP leakwatch_kanarie_gefunden Konnte der Lauf ueberhaupt finden?\n");
    out.push_str("# TYPE leakwatch_kanarie_gefunden gauge\n");
    for (source, ok) in canaries {
        let source = escape_label(source);
        out.push_str(&format!(
            "leakwatch_kanarie_gefunden{{quelle=\"{source}\"}} {}\n",
            u8::from(*ok)
        ));
    }
    out.push_str(&format!("leakwatch_lauf_zeitstempel {now}\n"));
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
        assert!(text.contains("leakwatch_treffer"));
        assert!(text.contains("radarr-apikey"));
        assert!(!text.contains("abc123"));
    }

    #[test]
    fn a_failed_canary_is_zero_not_absent() {
        let text = render(&[], &[("loki".into(), false)], 1758300000);
        assert!(text.contains("leakwatch_kanarie_gefunden{quelle=\"loki\"} 0"));
    }

    #[test]
    fn a_label_value_with_quotes_backslashes_and_a_newline_stays_one_line() {
        let nasty = "weird\"name\\with\nnewline".to_string();
        let text = render(&[(nasty, "journal".into(), 1)], &[], 1758300000);
        let treffer_line = text
            .lines()
            .find(|l| l.starts_with("leakwatch_treffer{"))
            .expect("no leakwatch_treffer line rendered");
        // The escaped newline must not have split the metric onto a second line.
        assert!(
            treffer_line.contains("\\n"),
            "newline not escaped: {treffer_line}"
        );
        assert!(
            treffer_line.contains("\\\""),
            "quote not escaped: {treffer_line}"
        );
        assert!(
            treffer_line.contains("\\\\"),
            "backslash not escaped: {treffer_line}"
        );
        // Quoting stays balanced: exactly two UNESCAPED double quotes bound each
        // label value (secret="..." and quelle="...").
        let unescaped_quotes = treffer_line
            .char_indices()
            .filter(|&(i, c)| c == '"' && !treffer_line.as_bytes()[..i].ends_with(b"\\"))
            .count();
        assert_eq!(unescaped_quotes, 4, "quoting not balanced: {treffer_line}");
    }
}
