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

/// A reader over a child's stdout that turns a failed command into an error
/// instead of an empty stream.
///
/// WHY THIS EXISTS: a failing `journalctl` or `curl` closes stdout immediately.
/// Without this, "the command did not run" and "this source is clean" look
/// exactly the same — and this tool exists to tell those apart.
pub(crate) struct ChildReader {
    inner: std::io::BufReader<std::process::ChildStdout>,
    child: std::process::Child,
    argv0: String,
    checked: bool,
}

impl std::io::Read for ChildReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n == 0 && !self.checked {
            self.checked = true;
            let status = self.child.wait()?;
            if !status.success() {
                let mut err = String::new();
                if let Some(mut e) = self.child.stderr.take() {
                    let _ = e.read_to_string(&mut err);
                }
                return Err(std::io::Error::other(format!(
                    "{} exited with {status}: {}",
                    self.argv0,
                    err.trim()
                )));
            }
        }
        Ok(n)
    }
}

/// Spawn a command and hand back its stdout as a streaming reader. A
/// non-zero exit surfaces as an `io::Error` on the read that hits EOF,
/// rather than as a silently empty stream.
pub(crate) fn spawn(argv: &[String]) -> Result<Box<dyn BufRead>> {
    use std::process::{Command, Stdio};
    let mut child = Command::new(&argv[0])
        .args(&argv[1..])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let out = child.stdout.take().expect("stdout piped");
    let argv0 = argv[0].clone();
    Ok(Box::new(std::io::BufReader::new(ChildReader {
        inner: std::io::BufReader::new(out),
        child,
        argv0,
        checked: false,
    })))
}

/// Reads a list of files as one stream, opening each only when the previous
/// one is exhausted.
///
/// WHY LAZY: opening all of them up front costs one descriptor per file — 991
/// for the session transcripts — and a systemd unit's default LimitNOFILE is
/// 1024. The failure would appear first where it hurts, under the sensor.
pub(crate) struct LazyFiles {
    rest: std::vec::IntoIter<std::path::PathBuf>,
    current: Option<std::io::BufReader<std::fs::File>>,
}

impl LazyFiles {
    pub(crate) fn new(paths: Vec<std::path::PathBuf>) -> Self {
        LazyFiles {
            rest: paths.into_iter(),
            current: None,
        }
    }
}

impl std::io::Read for LazyFiles {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self.current.is_none() {
                match self.rest.next() {
                    None => return Ok(0),
                    Some(path) => {
                        let f = std::fs::File::open(path)?;
                        self.current = Some(std::io::BufReader::new(f));
                    }
                }
            }
            let reader = self.current.as_mut().expect("just set above");
            let n = reader.read(buf)?;
            if n == 0 {
                self.current = None;
                continue;
            }
            return Ok(n);
        }
    }
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

    #[test]
    fn a_failing_command_is_an_error_not_an_empty_stream() {
        let argv = vec!["sh".to_string(), "-c".to_string(), "exit 3".to_string()];
        let mut r = spawn(&argv).expect("spawn itself succeeds");
        let mut s = String::new();
        let err = std::io::Read::read_to_string(&mut r, &mut s).unwrap_err();
        assert!(format!("{err}").contains("exited with"), "got: {err}");
    }

    #[test]
    fn a_succeeding_command_reads_its_output() {
        let argv = vec![
            "sh".to_string(),
            "-c".to_string(),
            "printf 'a\\nb\\n'".to_string(),
        ];
        let mut r = spawn(&argv).unwrap();
        let mut s = String::new();
        std::io::Read::read_to_string(&mut r, &mut s).unwrap();
        assert_eq!(s, "a\nb\n");
    }

    #[test]
    fn lazy_files_reads_several_files_as_one_stream() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.txt");
        let b = dir.path().join("b.txt");
        std::fs::write(&a, "one\n").unwrap();
        std::fs::write(&b, "two\n").unwrap();
        let mut lf = LazyFiles::new(vec![a, b]);
        let mut s = String::new();
        std::io::Read::read_to_string(&mut lf, &mut s).unwrap();
        assert_eq!(s, "one\ntwo\n");
    }

    #[test]
    fn lazy_files_surfaces_a_missing_file_as_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.txt");
        std::fs::write(&a, "one\n").unwrap();
        let missing = dir.path().join("does-not-exist.txt");
        let mut lf = LazyFiles::new(vec![a, missing]);
        let mut s = String::new();
        let err = std::io::Read::read_to_string(&mut lf, &mut s).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }
}
