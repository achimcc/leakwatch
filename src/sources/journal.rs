//! The journal of the host and of every guest.
//!
//! GUESTS OVER `journalctl -M`, NOT `systemd-run`: that avoids the whole
//! family of measurement mistakes in the homeserver notes (absolute path,
//! --wait, --collect) and, more importantly, never writes a key into argv —
//! which is what put 26 lines into the guest journals in the first place.

use super::{Source, spawn};
use anyhow::Result;
use std::io::BufRead;

pub struct Journal {
    pub machine: Option<String>,
    pub since: String,
    pub via_ssh: Option<String>,
}

impl Journal {
    pub fn command(&self) -> Vec<String> {
        let mut c = vec!["journalctl".to_string()];
        if let Some(m) = &self.machine {
            c.push("-M".into());
            c.push(m.clone());
        }
        // `short-iso` AND NOT `cat`, SO THE UNIT SURVIVES INTO THE REPORT.
        //
        // `cat` prints the message alone. The report could then name the
        // machine but never the service, and "which service writes this?" is
        // the question you need answered to fix a finding. On a real
        // installation on 2026-09-20 that cost an extra round on the host for
        // every triage: 101 lines in one guest mentioned `apikey` and exactly
        // one carried the value, so the answer only came from comparing
        // against the plaintext — something the person reading the report
        // often cannot do, and should not have to.
        //
        // The prefix is `<iso-date> <host> <unit>[<pid>]: <message>`; `locate`
        // pulls the unit back out of it. The extra text is scanned too, which
        // is harmless: it holds a date, a host name and a unit name.
        c.push("--output=short-iso".into());
        c.push("--no-pager".into());
        c.push("--since".into());
        c.push(format!("-{}", self.since));

        match &self.via_ssh {
            None => c,
            Some(target) => vec![
                "ssh".to_string(),
                "-o".to_string(),
                "IdentitiesOnly=yes".to_string(),
                target.clone(),
                c.join(" "),
            ],
        }
    }
}

/// The unit name out of a `journalctl --output=short-iso` line, if the line
/// looks like one.
///
/// The shape is `<iso-date> <host> <unit>[<pid>]: <message>`. Anything else
/// yields `None` — and that is a case that really occurs, not a formality:
/// the injected canary carries no journal prefix, and a multi-line message
/// continues without one.
///
/// DELIBERATELY STRICT ABOUT THE DATE: without that check any line whose
/// third word happens to end in a colon would donate a "unit" to the report,
/// and a location that is confidently wrong is worse than one that is
/// missing.
fn unit_of(line: &str) -> Option<&str> {
    let mut felder = line.split_whitespace();
    let datum = felder.next()?;
    if !datum.starts_with(|c: char| c.is_ascii_digit()) || !datum.contains('T') {
        return None;
    }
    let _host = felder.next()?;
    let dritte = felder.next()?;
    // `unit[pid]:` or `unit:` — cut at the first of `[` or `:`.
    let ende = dritte.find(['[', ':'])?;
    let unit = &dritte[..ende];
    if unit.is_empty() { None } else { Some(unit) }
}

impl Source for Journal {
    fn name(&self) -> &str {
        "journal"
    }
    fn open(&self) -> Result<Box<dyn BufRead>> {
        spawn(&self.command())
    }
    fn locate(&self, line: &str) -> (String, String) {
        let location = match (&self.via_ssh, &self.machine) {
            (Some(target), Some(m)) => format!("{}:{}", target, m),
            (Some(target), None) => target.clone(),
            (None, Some(m)) => m.clone(),
            (None, None) => "local".to_string(),
        };
        match unit_of(line) {
            Some(u) => ("journal".to_string(), format!("{location}/{u}")),
            None => ("journal".to_string(), location),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn j(machine: Option<&str>) -> Journal {
        Journal {
            machine: machine.map(str::to_string),
            since: "3h".into(),
            via_ssh: None,
        }
    }

    #[test]
    fn the_unit_comes_out_of_a_short_iso_line() {
        let line = "2026-09-20T13:06:19+0200 media-01 sonarr[1234]: [Warn] HttpClient: boom";
        assert_eq!(unit_of(line), Some("sonarr"));
    }

    #[test]
    fn a_line_without_a_pid_still_yields_the_unit() {
        let line = "2026-09-20T13:06:19+0200 media-01 kernel: something";
        assert_eq!(unit_of(line), Some("kernel"));
    }

    #[test]
    fn a_line_without_a_journal_prefix_yields_nothing() {
        // The injected canary and continuation lines look like this.
        assert_eq!(unit_of("just a bare line with a secret in it"), None);
        assert_eq!(unit_of(""), None);
    }

    #[test]
    fn a_third_word_ending_in_a_colon_is_not_mistaken_for_a_unit() {
        // No ISO date in front, so this must not donate a "unit".
        assert_eq!(unit_of("hello world note: text"), None);
    }

    #[test]
    fn locate_names_guest_and_unit_together() {
        let line = "2026-09-20T13:06:19+0200 media-01 sonarr[1234]: boom";
        let (source, location) = j(Some("media-01")).locate(line);
        assert_eq!(source, "journal");
        assert_eq!(
            location, "media-01/sonarr",
            "the report must name the service, not just the guest"
        );
    }

    #[test]
    fn locate_falls_back_to_the_guest_when_the_line_has_no_prefix() {
        let (_, location) = j(Some("media-01")).locate("bare canary line");
        assert_eq!(location, "media-01");
    }

    #[test]
    fn the_command_asks_for_short_iso_so_the_unit_is_there_to_parse() {
        let cmd = j(Some("media-01")).command();
        assert!(
            cmd.contains(&"--output=short-iso".to_string()),
            "without the prefix `locate` can never name a unit: {cmd:?}"
        );
        assert!(!cmd.contains(&"--output=cat".to_string()));
    }
}
