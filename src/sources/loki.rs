//! Loki, which also measures whether a log-scrubbing regex mask elsewhere
//! actually holds.
//!
//! LOKI IS OFTEN ONLY REACHABLE OVER SSH: it commonly listens on an
//! internal address a workstation cannot reach directly. Same pattern as
//! `gestalt`: the answer comes over `ssh … |`.
//!
//! PAGED, AND ONE LOG LINE PER SCANNED LINE. Up to v0.1.1 the adapter sent
//! one `query_range … &limit=5000` and scanned the raw JSON answer — which
//! is a single line. Measured on a real installation on 2026-09-27: 97 690
//! entries in three hours, 5 000 of them delivered, the answer 2 MB with
//! exactly one newline (audit 3, A2-2). The canary came back, so the run was
//! green while it saw five percent of the window, and a guest writing 5 000
//! lines just before each run could push everything else out of it.
//!
//! Now the window is walked oldest-first (`direction=forward`) in pages of
//! [`PAGE_LIMIT`]; the next page starts at the newest timestamp of the last
//! one, entries at that boundary already delivered are skipped, and every
//! `values[][1]` is its own line. A full page whose entries all share one
//! timestamp cannot be paged past — that is a read error, and the run fails
//! (exit 2) instead of reporting a truncated window as clean.

use super::{Source, spawn};
use anyhow::{Context, Result, bail};
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::io::{BufRead, Read};

/// Entries per request.
pub const PAGE_LIMIT: usize = 5000;

const QUERY: &str = "%7Bjob%3D%22systemd-journal%22%7D";

pub struct Loki {
    pub base: String,
    pub via_ssh: Option<String>,
    pub since: String,
}

impl Loki {
    /// The command for one page: entries with `start <= ts <= end` (ns),
    /// oldest first, at most `limit`.
    pub fn command(&self, start: u128, end: u128, limit: usize) -> Vec<String> {
        let url = format!(
            "{}/loki/api/v1/query_range?query={QUERY}&start={start}&end={end}&limit={limit}&direction=forward",
            self.base
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
            // QUOTED FOR THE REMOTE SHELL: ssh hands its command line to a
            // shell, and an unquoted `&` in the URL sent everything after the
            // first one into the background — the remote curl ran without
            // `limit` and `since`, i.e. with Loki's defaults (100 lines, one
            // hour), and the canary still made the run green.
            Some(target) => vec![
                "ssh".to_string(),
                "-o".to_string(),
                "IdentitiesOnly=yes".to_string(),
                target.clone(),
                curl.iter()
                    .map(|a| shell_quote(a))
                    .collect::<Vec<_>>()
                    .join(" "),
            ],
        }
    }

    fn window(&self) -> Result<(u128, u128)> {
        let secs = parse_duration(&self.since)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("system clock before 1970")?
            .as_nanos();
        Ok((now.saturating_sub(secs as u128 * 1_000_000_000), now))
    }
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// `30s`, `15m`, `3h`, `7d`, `2w` → seconds.
pub fn parse_duration(s: &str) -> Result<u64> {
    let s = s.trim();
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: u64 = num.parse().with_context(|| {
        format!("duration {s:?}: expected a number followed by s, m, h, d or w")
    })?;
    let factor = match unit {
        "s" => 1,
        "m" | "min" => 60,
        "h" => 3600,
        "d" => 86_400,
        "w" => 604_800,
        _ => bail!("duration {s:?}: unknown unit {unit:?} — use s, m, h, d or w"),
    };
    Ok(n * factor)
}

/// Fetches one page of `query_range` — a trait so a test can stand in for
/// Loki.
pub trait PageFetch {
    fn fetch(&mut self, start: u128, end: u128, limit: usize) -> Result<Vec<u8>>;
}

impl<F: FnMut(u128, u128, usize) -> Result<Vec<u8>>> PageFetch for F {
    fn fetch(&mut self, start: u128, end: u128, limit: usize) -> Result<Vec<u8>> {
        self(start, end, limit)
    }
}

/// One entry of a page: timestamp, a hash of stream labels plus line (to
/// recognise it again at a page boundary), and the line itself.
struct Entry {
    ts: u128,
    id: u64,
    line: String,
}

fn parse_page(body: &[u8]) -> Result<Vec<Entry>> {
    let v: serde_json::Value = serde_json::from_slice(body).context("Loki answer is not JSON")?;
    if v.get("status").and_then(|s| s.as_str()) != Some("success") {
        bail!("Loki answered without status \"success\"");
    }
    let data = v.get("data").context("Loki answer without data")?;
    if data.get("resultType").and_then(|s| s.as_str()) != Some("streams") {
        bail!("Loki answered with a resultType other than \"streams\"");
    }
    let result = data
        .get("result")
        .and_then(|r| r.as_array())
        .context("Loki answer without data.result")?;
    let mut out = Vec::new();
    for stream in result {
        let labels = stream
            .get("stream")
            .map(|l| l.to_string())
            .unwrap_or_default();
        let values = stream
            .get("values")
            .and_then(|v| v.as_array())
            .context("Loki stream without values")?;
        for pair in values {
            let ts = pair
                .get(0)
                .and_then(|t| t.as_str())
                .and_then(|t| t.parse::<u128>().ok())
                .context("Loki entry without a nanosecond timestamp")?;
            let line = pair
                .get(1)
                .and_then(|l| l.as_str())
                .context("Loki entry without a line")?
                .to_string();
            let mut h = std::collections::hash_map::DefaultHasher::new();
            labels.hash(&mut h);
            line.hash(&mut h);
            out.push(Entry {
                ts,
                id: h.finish(),
                line,
            });
        }
    }
    Ok(out)
}

/// The paged window as one stream of lines.
pub struct LokiPages<F: PageFetch> {
    fetch: F,
    start: u128,
    end: u128,
    limit: usize,
    /// Entries at timestamp `start` that were already delivered.
    boundary: HashSet<u64>,
    buf: std::io::Cursor<Vec<u8>>,
    done: bool,
    failed: Option<String>,
    /// Entries delivered so far — for the line-count metric and for tests.
    pub delivered: u64,
}

impl<F: PageFetch> LokiPages<F> {
    pub fn new(fetch: F, start: u128, end: u128, limit: usize) -> Self {
        LokiPages {
            fetch,
            start,
            end,
            limit,
            boundary: HashSet::new(),
            buf: std::io::Cursor::new(Vec::new()),
            done: false,
            failed: None,
            delivered: 0,
        }
    }

    fn next_page(&mut self) -> Result<()> {
        let body = self.fetch.fetch(self.start, self.end, self.limit)?;
        let mut entries = parse_page(&body)?;
        let full = entries.len() >= self.limit;
        entries.sort_by_key(|e| e.ts);
        let mut text = String::new();
        let mut fresh = 0usize;
        let max_ts = entries.last().map(|e| e.ts);
        for e in &entries {
            if e.ts < self.start || (e.ts == self.start && self.boundary.contains(&e.id)) {
                continue;
            }
            fresh += 1;
            // A log entry may itself hold newlines; each part is a line.
            text.push_str(&e.line);
            text.push('\n');
        }
        self.delivered += fresh as u64;
        self.buf = std::io::Cursor::new(text.into_bytes());
        if !full {
            self.done = true;
            return Ok(());
        }
        let max_ts = max_ts.expect("a full page is not empty");
        if fresh == 0 {
            bail!(
                "Loki returned a full page of {} entries at one timestamp ({max_ts}) — \
                 the window cannot be paged past it, and a truncated window is not a clean one",
                self.limit
            );
        }
        if max_ts != self.start {
            self.boundary.clear();
            self.start = max_ts;
        }
        for e in entries.iter().filter(|e| e.ts == max_ts) {
            self.boundary.insert(e.id);
        }
        Ok(())
    }
}

impl<F: PageFetch> Read for LokiPages<F> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if let Some(msg) = &self.failed {
                return Err(std::io::Error::other(msg.clone()));
            }
            let n = self.buf.read(out)?;
            if n > 0 || self.done {
                return Ok(n);
            }
            if let Err(e) = self.next_page() {
                self.failed = Some(format!("{e:#}"));
            }
        }
    }
}

impl Source for Loki {
    fn name(&self) -> &str {
        "loki"
    }
    fn open(&self) -> Result<Box<dyn BufRead>> {
        let (start, end) = self.window()?;
        // The fetcher owns what it needs: pages are fetched lazily, after
        // `open` has returned.
        let me = Loki {
            base: self.base.clone(),
            via_ssh: self.via_ssh.clone(),
            since: self.since.clone(),
        };
        let owned = move |start: u128, end: u128, limit: usize| -> Result<Vec<u8>> {
            let mut r = spawn(&me.command(start, end, limit))?;
            let mut body = Vec::new();
            r.read_to_end(&mut body)?;
            Ok(body)
        };
        Ok(Box::new(std::io::BufReader::new(LokiPages::new(
            owned, start, end, PAGE_LIMIT,
        ))))
    }
    fn locate(&self, _line: &str) -> (String, String) {
        ("loki".to_string(), self.base.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake Loki over a fixed set of (stream, ts, line) entries: answers
    /// `query_range` forward with at most `limit` entries, like the real one.
    fn fake(
        entries: Vec<(&'static str, u128, String)>,
    ) -> impl FnMut(u128, u128, usize) -> Result<Vec<u8>> {
        move |start, end, limit| {
            let mut sel: Vec<&(&str, u128, String)> = entries
                .iter()
                .filter(|(_, ts, _)| *ts >= start && *ts <= end)
                .collect();
            sel.sort_by_key(|(_, ts, _)| *ts);
            sel.truncate(limit);
            let mut streams: Vec<serde_json::Value> = Vec::new();
            for name in ["a", "b"] {
                let values: Vec<serde_json::Value> = sel
                    .iter()
                    .filter(|(s, _, _)| *s == name)
                    .map(|(_, ts, l)| serde_json::json!([ts.to_string(), l]))
                    .collect();
                if !values.is_empty() {
                    streams.push(serde_json::json!({"stream": {"unit": name}, "values": values}));
                }
            }
            Ok(serde_json::to_vec(&serde_json::json!({
                "status": "success",
                "data": {"resultType": "streams", "result": streams}
            }))?)
        }
    }

    fn read_all<F: PageFetch>(p: LokiPages<F>) -> std::io::Result<Vec<String>> {
        let mut r = std::io::BufReader::new(p);
        let mut s = String::new();
        r.read_to_string(&mut s)?;
        Ok(s.lines().map(str::to_string).collect())
    }

    #[test]
    fn every_entry_arrives_once_across_pages() {
        // 23 entries, pages of 5, two streams, several entries per timestamp
        // — including a boundary that falls in the middle of a timestamp.
        let entries: Vec<(&str, u128, String)> = (0..23u128)
            .map(|i| {
                (
                    if i % 2 == 0 { "a" } else { "b" },
                    100 + i / 3,
                    format!("line {i}"),
                )
            })
            .collect();
        let got = read_all(LokiPages::new(fake(entries), 0, 1000, 5)).unwrap();
        let mut sorted = got.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 23, "lost or duplicated entries: {got:?}");
        assert_eq!(got.len(), 23, "duplicated entries: {got:?}");
    }

    #[test]
    fn each_log_line_is_its_own_line_not_the_raw_json() {
        let entries = vec![
            ("a", 1, "first".to_string()),
            ("b", 2, "second".to_string()),
        ];
        let got = read_all(LokiPages::new(fake(entries), 0, 10, 5000)).unwrap();
        assert_eq!(got, vec!["first", "second"]);
    }

    #[test]
    fn a_full_page_that_cannot_be_paged_past_is_an_error() {
        // 7 entries on ONE timestamp, pages of 5: the second request starts at
        // the same timestamp and gets the same five back.
        let entries: Vec<(&str, u128, String)> =
            (0..7).map(|i| ("a", 42, format!("same ts {i}"))).collect();
        let err = read_all(LokiPages::new(fake(entries), 0, 100, 5)).unwrap_err();
        assert!(
            format!("{err}").contains("cannot be paged past"),
            "got: {err}"
        );
    }

    #[test]
    fn exactly_limit_entries_then_nothing_is_complete() {
        // A page that is exactly full is followed by one more request; if
        // that one brings nothing new, the window was complete.
        let entries: Vec<(&str, u128, String)> =
            (0..5u128).map(|i| ("a", i, format!("l{i}"))).collect();
        let got = read_all(LokiPages::new(fake(entries), 0, 100, 5));
        // The second page starts at ts 4 and returns only the already-seen
        // entry: fresh == 0 on a page that is NOT full → done.
        assert_eq!(got.unwrap().len(), 5);
    }

    #[test]
    fn a_non_success_answer_is_an_error() {
        let fetch = |_: u128, _: u128, _: usize| -> Result<Vec<u8>> {
            Ok(br#"{"status":"error","error":"x"}"#.to_vec())
        };
        assert!(read_all(LokiPages::new(fetch, 0, 1, 5)).is_err());
    }

    #[test]
    fn durations_parse() {
        assert_eq!(parse_duration("3h").unwrap(), 10_800);
        assert_eq!(parse_duration("7d").unwrap(), 604_800);
        assert_eq!(parse_duration("15m").unwrap(), 900);
        assert!(parse_duration("3x").is_err());
        assert!(parse_duration("h").is_err());
    }

    #[test]
    fn the_ssh_command_quotes_the_url_for_the_remote_shell() {
        let l = Loki {
            base: "http://192.0.2.12:3100".into(),
            via_ssh: Some("root@host.example.com".into()),
            since: "3h".into(),
        };
        let cmd = l.command(1, 2, 5000);
        let remote = cmd.last().unwrap();
        assert!(
            remote.contains("'http://192.0.2.12:3100/loki/api/v1/query_range?"),
            "{remote}"
        );
        assert!(
            remote.contains("&limit=5000&direction=forward'"),
            "{remote}"
        );
    }
}
