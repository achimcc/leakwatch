//! Counts what a scan found and covered, for export to a metrics endpoint.
//!
//! The textfile metric for the sensor — the house pattern (gast-speicher,
//! dns-abgleich, sicherung, groundtruth): timer, oneshot, written atomically.

pub fn render(hits: &[(String, String, u64)], canaries: &[(String, bool)], now: u64) -> String {
    let mut out = String::new();
    out.push_str("# HELP leakwatch_treffer Geheimnisse an Stellen, an die sie nicht gehoeren\n");
    out.push_str("# TYPE leakwatch_treffer gauge\n");
    for (secret, source, n) in hits {
        out.push_str(&format!(
            "leakwatch_treffer{{secret=\"{secret}\",quelle=\"{source}\"}} {n}\n"
        ));
    }
    out.push_str("# HELP leakwatch_kanarie_gefunden Konnte der Lauf ueberhaupt finden?\n");
    out.push_str("# TYPE leakwatch_kanarie_gefunden gauge\n");
    for (source, ok) in canaries {
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
}
