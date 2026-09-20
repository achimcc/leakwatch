//! Loki, which also measures whether a log-scrubbing regex mask elsewhere
//! actually holds.
//!
//! LOKI IS OFTEN ONLY REACHABLE OVER SSH: it commonly listens on an
//! internal address a workstation cannot reach directly. Same pattern as
//! `gestalt`: the answer comes over `ssh … |`.

use super::{Source, spawn};
use anyhow::Result;
use std::io::BufRead;

pub struct Loki {
    pub base: String,
    pub via_ssh: Option<String>,
    pub since: String,
}

impl Loki {
    pub fn command(&self) -> Vec<String> {
        let url = format!(
            "{}/loki/api/v1/query_range?query={}&since={}&limit=5000",
            self.base, "%7Bjob%3D%22systemd-journal%22%7D", self.since
        );
        // `-S` NEXT TO `-s`, AND IT IS NOT DECORATION. `-s` alone silences the
        // reason along with the progress meter: with `--fail`, curl exits 7
        // (could not connect) or 22 (HTTP >= 400) and prints nothing, so the
        // only thing left is an I/O error on the read — "reading a line",
        // which points at the read and means the address.
        //
        // Measured on a real installation on 2026-09-20: a sensor aimed at a
        // Loki that was not there reported `ERROR: loki: reading a line` and
        // cost a deploy cycle to diagnose. The same request run by hand with
        // `-sS` said `Failed to connect to localhost:3100` in the first
        // second. A tool whose job is diagnosis must not swallow the reason.
        let curl = vec![
            "curl".to_string(),
            "-sSG".to_string(),
            "--fail".to_string(),
            "--max-time".to_string(),
            "120".to_string(),
            url,
        ];
        match &self.via_ssh {
            None => curl,
            Some(target) => vec![
                "ssh".to_string(),
                "-o".to_string(),
                "IdentitiesOnly=yes".to_string(),
                target.clone(),
                curl.join(" "),
            ],
        }
    }
}

impl Source for Loki {
    fn name(&self) -> &str {
        "loki"
    }
    fn open(&self) -> Result<Box<dyn BufRead>> {
        spawn(&self.command())
    }
    fn locate(&self, _line: &str) -> (String, String) {
        ("loki".to_string(), self.base.clone())
    }
}
