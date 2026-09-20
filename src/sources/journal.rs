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
        c.push("--output=cat".into());
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

impl Source for Journal {
    fn name(&self) -> &str {
        "journal"
    }
    fn open(&self) -> Result<Box<dyn BufRead>> {
        spawn(&self.command())
    }
    fn locate(&self, _line: &str) -> (String, String) {
        let location = match (&self.via_ssh, &self.machine) {
            (Some(target), Some(m)) => format!("{}:{}", target, m),
            (Some(target), None) => target.clone(),
            (None, Some(m)) => m.clone(),
            (None, None) => "local".to_string(),
        };
        ("journal".to_string(), location)
    }
}
