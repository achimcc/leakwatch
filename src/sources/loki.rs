//! Loki, which also measures whether the regex mask in observability.nix
//! actually holds.
//!
//! THE AUDIT REACHES LOKI ONLY OVER SSH: the workstation cannot reach
//! 10.0.20.12:3100 — zone addresses are out of reach without a tailscale
//! route. Same pattern as `gestalt`: the answer comes over `ssh … |`.

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
        let curl = vec![
            "curl".to_string(),
            "-sG".to_string(),
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
