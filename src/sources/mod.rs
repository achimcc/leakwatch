//! Where lines come from. Four adapters, all streaming, none of them ever
//! carrying a secret in argv.

pub mod files;
pub mod journal;
pub mod loki;
pub mod sessions;

use anyhow::Result;
use std::io::BufRead;

pub trait Source {
    fn name(&self) -> &str;
    /// A streaming reader. Never reads the whole source into memory.
    fn open(&self) -> Result<Box<dyn BufRead>>;
    /// (source, location) for a finding — must never echo line content.
    fn locate(&self, line: &str) -> (String, String);
}

/// Spawn a command and hand back its stdout as a streaming reader.
pub(crate) fn spawn(argv: &[String]) -> Result<Box<dyn BufRead>> {
    use std::process::{Command, Stdio};
    let mut child = Command::new(&argv[0])
        .args(&argv[1..])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let out = child.stdout.take().expect("stdout piped");
    Ok(Box::new(std::io::BufReader::new(out)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_builds_the_host_command() {
        let j = journal::Journal {
            machine: None,
            since: "7d".into(),
        };
        let cmd = j.command();
        let got: Vec<&str> = cmd.iter().map(String::as_str).collect();
        assert_eq!(
            got,
            vec!["journalctl", "--output=cat", "--no-pager", "--since", "-7d"]
        );
    }

    #[test]
    fn journal_builds_the_guest_command_with_dash_m() {
        let j = journal::Journal {
            machine: Some("media-01".into()),
            since: "7d".into(),
        };
        assert!(j.command().contains(&"-M".to_string()));
        assert!(j.command().contains(&"media-01".to_string()));
    }

    #[test]
    fn journal_never_puts_a_secret_in_argv() {
        // The adapter never receives a value — that is the property that
        // keeps the tool from causing what it is looking for.
        let j = journal::Journal {
            machine: Some("media-01".into()),
            since: "7d".into(),
        };
        let joined = j.command().join(" ");
        assert!(!joined.contains("Api-Key"));
        assert!(!joined.contains("--header"));
    }

    #[test]
    fn loki_builds_a_direct_curl_command() {
        let l = loki::Loki {
            base: "http://10.0.20.12:3100".into(),
            via_ssh: None,
            since: "7d".into(),
        };
        let cmd = l.command();
        assert_eq!(cmd[0], "curl");
        assert!(cmd.iter().any(|a| a.contains("query_range")));
    }

    #[test]
    fn loki_wraps_the_call_in_ssh_when_asked() {
        let l = loki::Loki {
            base: "http://10.0.20.12:3100".into(),
            via_ssh: Some("root@server.taile9e283.ts.net".into()),
            since: "7d".into(),
        };
        let cmd = l.command();
        assert_eq!(cmd[0], "ssh");
        assert!(cmd.contains(&"root@server.taile9e283.ts.net".to_string()));
    }

    #[test]
    fn sessions_locate_names_the_file_and_nothing_else() {
        let s = sessions::Sessions {
            root: "/tmp/x".into(),
        };
        let (source, location) = s.locate("{\"uuid\":\"abc\"}");
        assert_eq!(source, "sessions");
        assert!(
            !location.contains("abc"),
            "content leaked into the location: {location}"
        );
    }
}
