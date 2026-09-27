//! The CLI: `leakwatch scan` audits on demand, `leakwatch sensor` runs from a
//! timer and additionally writes a Prometheus textfile metric.
//!
//! Both commands run the same pipeline per adapter: load secrets, build a
//! scanner that carries the canary alongside the real values, prove the
//! canary is even among its patterns, then for every source inject the
//! canary into the stream, scan it, and use the canary's fate — found or
//! not, alongside the source's own line count — to tell "nothing to find"
//! apart from "could not look". See `canary.rs` for why that distinction
//! needs proof, not a guess.

use anyhow::{Context, Result};
use leakwatch::canary;
use leakwatch::config::Config;
use leakwatch::metrics;
use leakwatch::report::{self, Finding};
use leakwatch::scan::Scanner;
use leakwatch::secrets::{self, RuntimeSecrets, Secrets, SopsSecrets};
use leakwatch::sources::Source;
use leakwatch::sources::files::Files;
use leakwatch::sources::journal::Journal;
use leakwatch::sources::loki::Loki;
use leakwatch::sources::sessions::Sessions;
use leakwatch::variants::{self, Kind};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const HELP: &str = "\
leakwatch — finds secrets in logs by matching their real plaintext values

USAGE:
    leakwatch scan   [OPTIONS]
    leakwatch sensor [OPTIONS]

scan runs a full audit and prints every finding as text, with the line
around it redacted. sensor runs the same audit, prints findings WITHOUT any
line content (name, source, location, time — its stdout is a journal), and
additionally writes a Prometheus textfile metric, meant for a timer-driven
oneshot (the gast-speicher/dns-abgleich/sicherung pattern).

Every value is searched in plaintext and in its encoded spellings (Base64,
URL-safe Base64, percent-encoding, JSON escapes, hex; single lines of a
multi-line value); a report names the spelling, e.g. `name[b64]`.

Every run injects its own canary in every spelling and proves, per adapter,
that each came back AND that the adapter delivered more than the canary.
A run that cannot prove this is a tool failure, never a clean result.

OPTIONS:
        --since DURATION     e.g. 7d, 1h (scan default: 7d, sensor default: 1h)
        --source LIST        comma-separated: journal,loki,sessions,files
                              (default: journal,loki,sessions for scan,
                              journal for sensor — files is never picked by
                              default, it needs --files)
        --machine NAME       scan a guest's journal via `journalctl -M NAME`
                              instead of the host's own; repeatable, several
                              guests can be scanned in one run
        --secrets-repo PATH  read secrets via sops from a homeserver-secrets
                              checkout instead of the local /run/secrets
        --secrets-root PATH  an ADDITIONAL runtime secrets root to search
                              alongside /run/secrets and
                              /run/secrets/rendered; repeatable
        --ssh TARGET         reach the journal or loki source over ssh (for
                              a machine the tool does not run on itself);
                              combine with --machine to reach a guest on a
                              remote host
        --loki-base URL      override the Loki base URL
                              (default: http://localhost:3100)
        --files GLOB         a glob for the files source; repeatable
        --sessions-root PATH override the sessions root
                              (default: ~/.claude/projects)
    -c, --config FILE        exceptions, see README (every one needs a reason)
        --output PATH        sensor: where to write the textfile metric
                              (default: /var/lib/node-exporter/leakwatch.prom)
    -h, --help
    -V, --version

EXIT STATUS:
    0  no findings, every canary found, no source silent
    1  findings
    2  tool failure — canary missing or not found, a source silent, unused
       exceptions, or an adapter error
";

const DEFAULT_LOKI_BASE: &str = "http://localhost:3100";
const DEFAULT_SENSOR_OUTPUT: &str = "/var/lib/node-exporter/leakwatch.prom";

#[derive(Default)]
struct Args {
    command: String,
    since: Option<String>,
    sources: Option<String>,
    machine: Vec<String>,
    secrets_repo: Option<PathBuf>,
    secrets_root: Vec<PathBuf>,
    ssh: Option<String>,
    loki_base: Option<String>,
    files: Vec<String>,
    sessions_root: Option<PathBuf>,
    config: Option<PathBuf>,
    output: Option<PathBuf>,
}

fn parse_args() -> Result<Option<Args>, lexopt::Error> {
    use lexopt::prelude::*;
    let mut a = Args::default();
    let mut p = lexopt::Parser::from_env();
    while let Some(arg) = p.next()? {
        match arg {
            Long("since") => a.since = Some(p.value()?.string()?),
            Long("source") => a.sources = Some(p.value()?.string()?),
            Long("machine") => a.machine.push(p.value()?.string()?),
            Long("secrets-repo") => a.secrets_repo = Some(p.value()?.into()),
            Long("secrets-root") => a.secrets_root.push(p.value()?.into()),
            Long("ssh") => a.ssh = Some(p.value()?.string()?),
            Long("loki-base") => a.loki_base = Some(p.value()?.string()?),
            Long("files") => a.files.push(p.value()?.string()?),
            Long("sessions-root") => a.sessions_root = Some(p.value()?.into()),
            Short('c') | Long("config") => a.config = Some(p.value()?.into()),
            Long("output") => a.output = Some(p.value()?.into()),
            Short('h') | Long("help") => {
                print!("{HELP}");
                return Ok(None);
            }
            Short('V') | Long("version") => {
                println!("leakwatch {}", env!("CARGO_PKG_VERSION"));
                return Ok(None);
            }
            Value(v) if a.command.is_empty() => a.command = v.string()?,
            _ => return Err(arg.unexpected()),
        }
    }
    Ok(Some(a))
}

fn default_sessions_root() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".claude/projects")
}

fn default_runtime_roots() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/run/secrets"),
        PathBuf::from("/run/secrets/rendered"),
    ]
}

fn load_secrets(repo: &Option<PathBuf>, extra_roots: &[PathBuf]) -> Result<Vec<(String, String)>> {
    match repo {
        Some(r) => SopsSecrets { repo: r.clone() }.load(),
        None => {
            // Additive, not a replacement: a caller who adds one root must not
            // silently lose /run/secrets/rendered because they forgot to name
            // it too.
            let mut roots = default_runtime_roots();
            roots.extend(extra_roots.iter().cloned());
            RuntimeSecrets { roots }.load()
        }
    }
}

fn load_config(path: &Option<PathBuf>) -> Result<Config> {
    let config = match path {
        None => Config::default(),
        Some(p) => {
            let text =
                std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?;
            toml::from_str(&text).with_context(|| format!("parsing {}", p.display()))?
        }
    };
    // Catch a canary exception here, before any source runs — it would
    // otherwise surface much later as a plain "unused exception", pointing
    // an operator at the wrong cause.
    config.validate()?;
    Ok(config)
}

fn parse_source_list(raw: &Option<String>, default: &[&str]) -> Vec<String> {
    match raw {
        Some(s) => s
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect(),
        None => default.iter().map(|s| s.to_string()).collect(),
    }
}

#[allow(clippy::too_many_arguments)]
fn build_sources(
    names: &[String],
    since: &str,
    ssh: &Option<String>,
    loki_base: &str,
    files: &[String],
    sessions_root: &Option<PathBuf>,
    machines: &[String],
) -> Result<Vec<Box<dyn Source>>> {
    let mut out: Vec<Box<dyn Source>> = Vec::new();
    for n in names {
        match n.as_str() {
            "journal" => {
                if machines.is_empty() {
                    out.push(Box::new(Journal {
                        machine: None,
                        since: since.to_string(),
                        via_ssh: ssh.clone(),
                    }));
                } else {
                    for m in machines {
                        out.push(Box::new(Journal {
                            machine: Some(m.clone()),
                            since: since.to_string(),
                            via_ssh: ssh.clone(),
                        }));
                    }
                }
            }
            "loki" => out.push(Box::new(Loki {
                base: loki_base.to_string(),
                via_ssh: ssh.clone(),
                since: since.to_string(),
            })),
            "sessions" => out.push(Box::new(Sessions {
                root: sessions_root.clone().unwrap_or_else(default_sessions_root),
            })),
            "files" => {
                if files.is_empty() {
                    anyhow::bail!("the files source needs at least one --files glob");
                }
                out.push(Box::new(Files {
                    globs: files.to_vec(),
                }));
            }
            other => anyhow::bail!("unknown source {other} — use journal, loki, sessions or files"),
        }
    }
    Ok(out)
}

/// The mutable bookkeeping one adapter's scan writes into.
struct RunState {
    out_lines: Vec<String>,
    matched_pairs: HashSet<(String, String)>,
    counts: HashMap<(String, String), u64>,
    findings: usize,
    /// Print the redacted line around a finding (`scan`) or only name,
    /// source, location and time (`sensor`, whose stdout is the journal).
    with_context: bool,
}

/// What one source's scan established.
struct SourceResult {
    /// Lines the source itself delivered — the probes not counted.
    own_lines: u64,
    /// Kinds whose probe did not come back. Empty: the canary was found in
    /// every spelling.
    missing: Vec<&'static str>,
}

/// Scan one source.
fn process_source(
    source: &dyn Source,
    scanner: &Scanner,
    probes: &[canary::Probe],
    config: &Config,
    now: &str,
    state: &mut RunState,
) -> Result<SourceResult> {
    let name = source.name().to_string();
    let mut proven = vec![false; probes.len()];
    let reader = source.open()?;
    let wrapped = canary::inject(probes, reader);
    let lines = scanner.scan_stream_grouped(wrapped, &mut |text, hits, all_spans| {
        if let Some(i) = canary::probe_index(text)
            && let Some(p) = probes.get(i)
            && canary::proves(p, hits)
        {
            proven[i] = true;
        }
        // The canary proves the wiring works — it is never a finding. Its
        // spans stay in `all_spans` and are masked like every other.
        let mut kept: Vec<(String, (usize, usize))> = Vec::new();
        for (secret, span) in hits {
            let base = variants::base_name(secret);
            if base == canary::CANARY_NAME {
                continue;
            }
            state
                .matched_pairs
                .insert((secret.to_string(), name.clone()));
            state.matched_pairs.insert((base.to_string(), name.clone()));
            if config.excepted(secret, &name) {
                continue;
            }
            // The metric keys on the secret's own name: that is what the
            // alert rule hands to `just rotor-leser`. The report names the
            // spelling.
            *state
                .counts
                .entry((base.to_string(), name.clone()))
                .or_insert(0) += 1;
            kept.push((secret.clone(), *span));
        }
        if kept.is_empty() {
            return;
        }
        // `locate` gets the REDACTED text: it must never echo line content,
        // and a unit name pulled from a prefix that held a secret would.
        let (source_field, location) = source.locate(&report::redact(text, all_spans));
        for finding in Finding::from_hits(text, &kept, all_spans, &source_field, &location, now) {
            state.out_lines.push(if state.with_context {
                report::format(&finding)
            } else {
                report::format_brief(&finding)
            });
            state.findings += 1;
        }
    })?;
    let mut missing: Vec<&'static str> = Vec::new();
    for (p, ok) in probes.iter().zip(&proven) {
        let label = match p.kind {
            Kind::Plain => "plain",
            k => k.suffix(),
        };
        if !ok && !missing.contains(&label) {
            missing.push(label);
        }
    }
    Ok(SourceResult {
        own_lines: lines.saturating_sub(probes.len() as u64),
        missing,
    })
}

struct Outcome {
    report: String,
    exit_code: u8,
    hits: Vec<(String, String, u64)>,
    canaries: Vec<(String, bool)>,
    lines: Vec<(String, u64)>,
    now: u64,
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Run the full pipeline shared by `scan` and `sensor`.
fn execute(
    sources: Vec<Box<dyn Source>>,
    all_secrets: Vec<(String, String)>,
    config: &Config,
    with_context: bool,
) -> Result<Outcome> {
    let all_count = all_secrets.len();
    let multiline = secrets::multiline_note(&all_secrets);

    // The canary rides in the SAME scanner as the real secrets — a separate
    // scanner would prove nothing about the one actually used.
    // Every canary value, in every spelling the scanner builds for it.
    let mut with_canary = all_secrets;
    with_canary.extend(canary::secrets());
    let scanner = Scanner::new(with_canary)?;
    let probes = canary::probes(&scanner);

    if !canary::check(&scanner) {
        anyhow::bail!(
            "the canary is not among the scanner's patterns — nothing this run finds can be trusted"
        );
    }

    let now = now_unix();
    let now_str = now.to_string();

    let mut state = RunState {
        out_lines: Vec::new(),
        matched_pairs: HashSet::new(),
        counts: HashMap::new(),
        findings: 0,
        with_context,
    };
    let mut canaries: Vec<(String, bool)> = Vec::new();
    let mut line_counts: Vec<(String, u64)> = Vec::new();
    let mut tool_failure = false;

    for source in &sources {
        let name = source.name().to_string();
        // WHICH one — the metric folds several sources of the same name into
        // one line (see `metrics::render`), so the error line is the only
        // place that can still say WHICH guest was silent. Without it
        // "journal: the source itself was silent" points at 33 candidates.
        // `locate` ignores the line for every adapter, so an empty one is
        // enough to ask for the location.
        let (_, wo) = source.locate("");
        let woher = if wo == name {
            name.clone()
        } else {
            format!("{name} ({wo})")
        };
        match process_source(
            source.as_ref(),
            &scanner,
            &probes,
            config,
            &now_str,
            &mut state,
        ) {
            Ok(r) => {
                let canary_found = r.missing.is_empty();
                if !canary_found {
                    state.out_lines.push(format!(
                        "ERROR: {woher}: canary not found (spellings: {}) — this run proves nothing",
                        r.missing.join(", ")
                    ));
                    tool_failure = true;
                } else if r.own_lines == 0 {
                    state.out_lines.push(format!(
                        "ERROR: {woher}: only the canary arrived — the source itself was silent"
                    ));
                    tool_failure = true;
                }
                canaries.push((name.clone(), canary_found));
                line_counts.push((name, r.own_lines));
            }
            Err(e) => {
                state.out_lines.push(format!("ERROR: {woher}: {e:#}"));
                tool_failure = true;
                canaries.push((name.clone(), false));
                line_counts.push((name, 0));
            }
        }
    }

    let matched: Vec<(String, String)> = state.matched_pairs.iter().cloned().collect();
    let unused = config.unused(&matched);
    if !unused.is_empty() {
        for u in &unused {
            state
                .out_lines
                .push(format!("ERROR: exception no longer matches anything: {u}"));
        }
        tool_failure = true;
    }

    state
        .out_lines
        .push(secrets::skipped_short(all_count, scanner.pattern_count()));
    state.out_lines.push(format!(
        "{} encoded spellings and lines searched alongside (base64, url, json, hex, line)",
        scanner.variant_count()
    ));
    if let Some(note) = multiline {
        state.out_lines.push(note);
    }

    let exit_code: u8 = if tool_failure {
        2
    } else if state.findings > 0 {
        1
    } else {
        0
    };

    let hits: Vec<(String, String, u64)> = state
        .counts
        .into_iter()
        .map(|((s, src), n)| (s, src, n))
        .collect();

    let mut report_text = state.out_lines.join("\n");
    if !report_text.is_empty() {
        report_text.push('\n');
    }

    Ok(Outcome {
        report: report_text,
        exit_code,
        hits,
        canaries,
        lines: line_counts,
        now,
    })
}

/// Write text to `path` by writing a sibling temp file and renaming it —
/// never a partial file where a reader (node-exporter's textfile collector)
/// might see it.
fn write_metrics_atomically(path: &Path, text: &str) -> Result<()> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let tmp = dir.join(format!(
        ".{}.tmp.{}",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("leakwatch"),
        std::process::id()
    ));
    std::fs::write(&tmp, text).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("renaming into {}", path.display()))?;
    Ok(())
}

fn run_scan(a: &Args) -> Result<Outcome> {
    let config = load_config(&a.config)?;
    let since = a.since.clone().unwrap_or_else(|| "7d".to_string());
    // "files" is deliberately not in the default list — it needs a real
    // glob, and a guessed one is not a finding, it is a false promise.
    let names = parse_source_list(&a.sources, &["journal", "loki", "sessions"]);
    let loki_base = a
        .loki_base
        .clone()
        .unwrap_or_else(|| DEFAULT_LOKI_BASE.to_string());
    let sources = build_sources(
        &names,
        &since,
        &a.ssh,
        &loki_base,
        &a.files,
        &a.sessions_root,
        &a.machine,
    )?;
    let secrets = load_secrets(&a.secrets_repo, &a.secrets_root)?;
    execute(sources, secrets, &config, true)
}

fn run_sensor(a: &Args) -> Result<(Outcome, PathBuf)> {
    let config = load_config(&a.config)?;
    let since = a.since.clone().unwrap_or_else(|| "1h".to_string());
    let names = parse_source_list(&a.sources, &["journal"]);
    let loki_base = a
        .loki_base
        .clone()
        .unwrap_or_else(|| DEFAULT_LOKI_BASE.to_string());
    let sources = build_sources(
        &names,
        &since,
        &a.ssh,
        &loki_base,
        &a.files,
        &a.sessions_root,
        &a.machine,
    )?;
    let secrets = load_secrets(&a.secrets_repo, &a.secrets_root)?;
    // No line context from the sensor: its stdout is the host journal, and
    // from there Loki and every chat log that quotes it (audit 3, A2-1).
    let outcome = execute(sources, secrets, &config, false)?;
    let output = a
        .output
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SENSOR_OUTPUT));
    Ok((outcome, output))
}

fn run_command(a: &Args) -> Result<u8> {
    match a.command.as_str() {
        "scan" => {
            let outcome = run_scan(a)?;
            print!("{}", outcome.report);
            Ok(outcome.exit_code)
        }
        "sensor" => {
            let (outcome, output) = run_sensor(a)?;
            print!("{}", outcome.report);
            let text = metrics::render(
                &outcome.hits,
                &outcome.canaries,
                &outcome.lines,
                outcome.now,
            );
            write_metrics_atomically(&output, &text)?;
            Ok(outcome.exit_code)
        }
        "" => anyhow::bail!("missing command: scan or sensor — try --help"),
        other => anyhow::bail!("unknown command {other} — try --help"),
    }
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(Some(a)) => a,
        Ok(None) => return ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("leakwatch: {e}\nTry `leakwatch --help`.");
            return ExitCode::from(2);
        }
    };
    match run_command(&args) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("leakwatch: {e:#}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_machine_yields_the_host_journal() {
        let sources = build_sources(
            &["journal".to_string()],
            "7d",
            &None,
            "http://localhost:3100",
            &[],
            &None,
            &[],
        )
        .unwrap();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].locate("line").1, "local");
    }

    #[test]
    fn one_machine_yields_one_guest_source() {
        let sources = build_sources(
            &["journal".to_string()],
            "7d",
            &None,
            "http://localhost:3100",
            &[],
            &None,
            &["media-01".to_string()],
        )
        .unwrap();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].locate("line").1, "media-01");
    }

    #[test]
    fn two_machines_yield_two_guest_sources() {
        let sources = build_sources(
            &["journal".to_string()],
            "7d",
            &None,
            "http://localhost:3100",
            &[],
            &None,
            &["media-01".to_string(), "jelly-01".to_string()],
        )
        .unwrap();
        assert_eq!(sources.len(), 2);
        assert_eq!(sources[0].locate("line").1, "media-01");
        assert_eq!(sources[1].locate("line").1, "jelly-01");
    }

    // ------------------------------------------------ audit 3 (2026-09-27)

    const A: &str = "Zq7Xw2mP9vK4tR8sL1nB";
    const B: &str = "hH3jJ5kK7lL9zZ1xX3cC";

    fn secrets_ab() -> Vec<(String, String)> {
        vec![("probe-a".into(), A.into()), ("probe-b".into(), B.into())]
    }

    fn file_source(dir: &tempfile::TempDir, content: &str) -> Vec<Box<dyn Source>> {
        let path = dir.path().join("x.log");
        std::fs::write(&path, content).unwrap();
        vec![Box::new(Files {
            globs: vec![path.to_string_lossy().to_string()],
        })]
    }

    #[test]
    fn sensor_prints_no_line_content() {
        let dir = tempfile::tempdir().unwrap();
        let src = file_source(
            &dir,
            &format!("distinct-context-word user={B} pass={A} retry={A}\nclean\n"),
        );
        let o = execute(src, secrets_ab(), &Config::default(), false).unwrap();
        assert_eq!(o.exit_code, 1, "{}", o.report);
        assert!(!o.report.contains(A) && !o.report.contains(B));
        assert!(!o.report.contains("distinct-context-word"), "{}", o.report);
        assert!(!o.report.contains(report::MASK), "{}", o.report);
        assert!(o.report.contains("probe-a") && o.report.contains("probe-b"));
    }

    #[test]
    fn scan_prints_context_with_every_secret_masked() {
        let dir = tempfile::tempdir().unwrap();
        let src = file_source(&dir, &format!("ctx user={B} pass={A} retry={A}\nclean\n"));
        let o = execute(src, secrets_ab(), &Config::default(), true).unwrap();
        assert_eq!(o.exit_code, 1, "{}", o.report);
        assert!(
            !o.report.contains(A) && !o.report.contains(B),
            "{}",
            o.report
        );
        assert!(
            o.report
                .contains("ctx user=<REDACTED> pass=<REDACTED> retry=<REDACTED>")
        );
    }

    #[test]
    fn an_encoded_hit_is_named_by_spelling_and_counted_under_the_secret() {
        let dir = tempfile::tempdir().unwrap();
        let basic = variants::b64(format!("user:{A}").as_bytes(), variants::B64_STD);
        let src = file_source(&dir, &format!("Authorization: Basic {basic}\nclean\n"));
        let o = execute(src, secrets_ab(), &Config::default(), true).unwrap();
        assert_eq!(o.exit_code, 1, "{}", o.report);
        assert!(o.report.contains("probe-a[b64]"), "{}", o.report);
        assert!(
            o.report.contains("just rotor-leser probe-a\n")
                || o.report.ends_with("just rotor-leser probe-a")
        );
        assert_eq!(
            o.hits,
            vec![("probe-a".to_string(), "files".to_string(), 1)]
        );
    }

    #[test]
    fn an_exception_for_the_secret_covers_its_spellings() {
        let dir = tempfile::tempdir().unwrap();
        let hex = variants::hex(A.as_bytes(), false);
        let src = file_source(&dir, &format!("dump {hex}\nclean\n"));
        let config: Config = toml::from_str(
            "[[exception]]\nsecret = \"probe-a\"\nsource = \"files\"\nreason = \"test\"\n",
        )
        .unwrap();
        let o = execute(src, secrets_ab(), &config, true).unwrap();
        assert_eq!(o.exit_code, 0, "{}", o.report);
    }

    #[test]
    fn a_clean_source_proves_the_canary_in_every_spelling() {
        let dir = tempfile::tempdir().unwrap();
        let src = file_source(&dir, "nothing\nhere\n");
        let o = execute(src, secrets_ab(), &Config::default(), false).unwrap();
        assert_eq!(o.exit_code, 0, "{}", o.report);
        assert_eq!(o.canaries, vec![("files".to_string(), true)]);
        assert_eq!(o.lines, vec![("files".to_string(), 2)]);
    }

    /// A Loki stand-in: the real paging reader over a fake fetcher.
    struct FakeLoki {
        entries: Vec<(u128, String)>,
    }

    impl Source for FakeLoki {
        fn name(&self) -> &str {
            "loki"
        }
        fn open(&self) -> Result<Box<dyn std::io::BufRead>> {
            use leakwatch::sources::loki::LokiPages;
            let entries = self.entries.clone();
            let fetch = move |start: u128, end: u128, limit: usize| -> Result<Vec<u8>> {
                let mut sel: Vec<&(u128, String)> = entries
                    .iter()
                    .filter(|(ts, _)| *ts >= start && *ts <= end)
                    .collect();
                sel.sort_by_key(|(ts, _)| *ts);
                sel.truncate(limit);
                let values: Vec<serde_json::Value> = sel
                    .iter()
                    .map(|(ts, l)| serde_json::json!([ts.to_string(), l]))
                    .collect();
                Ok(serde_json::to_vec(&serde_json::json!({
                    "status": "success",
                    "data": {"resultType": "streams",
                             "result": [{"stream": {"job": "systemd-journal"}, "values": values}]}
                }))?)
            };
            Ok(Box::new(std::io::BufReader::new(LokiPages::new(
                fetch,
                0,
                u128::MAX,
                leakwatch::sources::loki::PAGE_LIMIT,
            ))))
        }
        fn locate(&self, _line: &str) -> (String, String) {
            ("loki".into(), "fake".into())
        }
    }

    #[test]
    fn loki_scans_every_entry_of_a_window_larger_than_one_page() {
        // 12 000 entries, the leak at 9 000 — far behind the first page.
        let entries: Vec<(u128, String)> = (0..12_000u128)
            .map(|i| {
                let line = if i == 9_000 {
                    format!("GET /api?apikey={A}")
                } else {
                    format!("line {i}")
                };
                (1_000 + i, line)
            })
            .collect();
        let src: Vec<Box<dyn Source>> = vec![Box::new(FakeLoki { entries })];
        let o = execute(src, secrets_ab(), &Config::default(), false).unwrap();
        assert_eq!(o.exit_code, 1, "{}", o.report);
        assert_eq!(o.hits, vec![("probe-a".to_string(), "loki".to_string(), 1)]);
        assert_eq!(o.lines, vec![("loki".to_string(), 12_000)]);
    }

    #[test]
    fn loki_that_cannot_be_paged_is_a_tool_failure() {
        // More than one page of entries on a single timestamp.
        let entries: Vec<(u128, String)> = (0..(leakwatch::sources::loki::PAGE_LIMIT + 1))
            .map(|i| (7, format!("same ts {i}")))
            .collect();
        let src: Vec<Box<dyn Source>> = vec![Box::new(FakeLoki { entries })];
        let o = execute(src, secrets_ab(), &Config::default(), false).unwrap();
        assert_eq!(o.exit_code, 2, "{}", o.report);
        assert!(o.report.contains("cannot be paged past"), "{}", o.report);
        assert_eq!(o.canaries, vec![("loki".to_string(), false)]);
    }
}
