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

/// Where a `ChildReader` stands relative to the child's exit. Distinguishing
/// `Failed` from "not checked yet" is what stops a second `read()` after an
/// error from silently reporting a clean end of stream: once failed, it
/// stays failed on every subsequent call.
enum ChildState {
    Running,
    Done,
    Failed(String),
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
    // Drains stderr on its own thread, started at construction time — NOT
    // read synchronously after `wait()`. A pipe holds only ~64 KiB; a child
    // that writes more than that to stderr (a `curl -v`, a chatty `ssh`
    // banner, a journal full of parse warnings) blocks on the write end
    // until someone reads it, and `wait()` cannot return while the child is
    // blocked. Reading stderr only after `wait()` is therefore a deadlock
    // waiting for a large-enough error message, not a simplification of this
    // code — do not fold it back into a synchronous read.
    stderr_collector: Option<std::thread::JoinHandle<Vec<u8>>>,
    state: ChildState,
}

impl std::io::Read for ChildReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if let ChildState::Failed(msg) = &self.state {
            return Err(std::io::Error::other(msg.clone()));
        }
        let n = self.inner.read(buf)?;
        if n == 0 && matches!(self.state, ChildState::Running) {
            let status = self.child.wait()?;
            if !status.success() {
                let err_bytes = self
                    .stderr_collector
                    .take()
                    .and_then(|h| h.join().ok())
                    .unwrap_or_default();
                let err_text = String::from_utf8_lossy(&err_bytes).trim().to_string();
                let msg = format!("{} exited with {status}: {err_text}", self.argv0);
                self.state = ChildState::Failed(msg.clone());
                return Err(std::io::Error::other(msg));
            }
            self.state = ChildState::Done;
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
    // Drain stderr concurrently — see the comment on `stderr_collector`.
    let stderr_collector = child.stderr.take().map(|mut e| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            use std::io::Read as _;
            let _ = e.read_to_end(&mut buf);
            buf
        })
    });
    Ok(Box::new(std::io::BufReader::new(ChildReader {
        inner: std::io::BufReader::new(out),
        child,
        argv0,
        stderr_collector,
        state: ChildState::Running,
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
            via_ssh: None,
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
            via_ssh: None,
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
            via_ssh: None,
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
        assert!(
            cmd.contains(&"--fail".to_string()),
            "curl without --fail treats an HTTP error as success: {cmd:?}"
        );
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
        assert!(
            cmd.iter().any(|a| a.contains("--fail")),
            "the ssh-wrapped curl call must carry --fail too: {cmd:?}"
        );
    }

    #[test]
    fn journal_local_command_unchanged_by_via_ssh_none() {
        let j = journal::Journal {
            machine: None,
            since: "7d".into(),
            via_ssh: None,
        };
        let cmd = j.command();
        let got: Vec<&str> = cmd.iter().map(String::as_str).collect();
        assert_eq!(
            got,
            vec!["journalctl", "--output=cat", "--no-pager", "--since", "-7d"]
        );
    }

    #[test]
    fn journal_wraps_the_call_in_ssh_when_asked() {
        let j = journal::Journal {
            machine: None,
            since: "7d".into(),
            via_ssh: Some("root@server.taile9e283.ts.net".into()),
        };
        let cmd = j.command();
        assert_eq!(cmd[0], "ssh");
        assert!(cmd.contains(&"root@server.taile9e283.ts.net".to_string()));
        assert!(
            cmd.iter().any(|a| a.contains("journalctl")),
            "the ssh-wrapped journalctl call must contain journalctl: {cmd:?}"
        );
    }

    #[test]
    fn journal_guest_with_ssh_produces_well_formed_command() {
        let j = journal::Journal {
            machine: Some("media-01".into()),
            since: "7d".into(),
            via_ssh: Some("root@server.taile9e283.ts.net".into()),
        };
        let cmd = j.command();
        assert_eq!(cmd[0], "ssh");
        assert!(cmd.contains(&"root@server.taile9e283.ts.net".to_string()));
        // The joined command must contain both -M and the guest name
        let joined = cmd.join(" ");
        assert!(
            joined.contains("-M"),
            "ssh-wrapped journalctl must include -M flag: {joined}"
        );
        assert!(
            joined.contains("media-01"),
            "ssh-wrapped journalctl must include guest name: {joined}"
        );
    }

    #[test]
    fn journal_locate_returns_different_locations_for_local_and_remote() {
        let local = journal::Journal {
            machine: Some("media-01".into()),
            since: "7d".into(),
            via_ssh: None,
        };
        let (_, local_loc) = local.locate("test line");
        assert_eq!(local_loc, "media-01", "local should show only machine name");

        let remote = journal::Journal {
            machine: Some("media-01".into()),
            since: "7d".into(),
            via_ssh: Some("root@server.taile9e283.ts.net".into()),
        };
        let (_, remote_loc) = remote.locate("test line");
        assert_eq!(
            remote_loc, "root@server.taile9e283.ts.net:media-01",
            "remote should include target and machine"
        );
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
    fn a_second_read_after_a_failure_still_errors() {
        let argv = vec!["sh".to_string(), "-c".to_string(), "exit 3".to_string()];
        let mut r = spawn(&argv).expect("spawn itself succeeds");
        let mut buf = [0u8; 16];
        let first = std::io::Read::read(&mut r, &mut buf);
        assert!(first.is_err(), "first read should already fail");
        let second = std::io::Read::read(&mut r, &mut buf);
        assert!(
            second.is_err(),
            "a second read after a failure must not look like a clean EOF"
        );
    }

    #[test]
    fn a_chatty_stderr_does_not_deadlock_a_failing_command() {
        // The deadlock this guards against: `wait()` cannot return while the
        // child blocks writing more than a pipe buffer (~64 KiB) of stderr
        // that nobody is reading. 200 KB comfortably exceeds that.
        let argv = vec![
            "sh".to_string(),
            "-c".to_string(),
            "yes errortext | head -c 200000 >&2; exit 4".to_string(),
        ];
        let mut r = spawn(&argv).expect("spawn itself succeeds");
        let mut s = String::new();
        let err = std::io::Read::read_to_string(&mut r, &mut s).unwrap_err();
        assert!(format!("{err}").contains("exited with"), "got: {err}");
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
