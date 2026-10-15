//! B221 (audit 4): with `--machine` the host's own journal used to drop out
//! of the run. What a log-store mask misses lies raw in the host journal, so
//! a sensor that lists its guests must still read the host.
//!
//! The test puts a fake `journalctl` first on PATH: it prints a few filler
//! lines for every call, and the secret value only when called WITHOUT `-M`
//! — i.e. only in the host journal. A run with `--machine` must find it.

use std::os::unix::fs::PermissionsExt;
use std::process::Command;

const SECRET: &str = "Hq8Lw3nV7cX2pT5rK9mZ";

fn fake_journalctl(dir: &std::path::Path) {
    let script = format!(
        "#!/bin/sh\n\
         for a in \"$@\"; do [ \"$a\" = -M ] && guest=1; done\n\
         printf '2026-10-16T10:00:00+0200 h unit-a[1]: filler one\\n'\n\
         printf '2026-10-16T10:00:01+0200 h unit-a[1]: filler two\\n'\n\
         printf '2026-10-16T10:00:02+0200 h unit-a[1]: filler three\\n'\n\
         if [ -z \"$guest\" ]; then\n\
           printf '2026-10-16T10:00:03+0200 h leaky[7]: token={SECRET}\\n'\n\
         fi\n"
    );
    let path = dir.join("journalctl");
    std::fs::write(&path, script).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn a_canary_in_the_host_journal_is_found_even_with_machines_listed() {
    let bin = tempfile::tempdir().unwrap();
    fake_journalctl(bin.path());
    let secrets = tempfile::tempdir().unwrap();
    std::fs::write(secrets.path().join("api-key"), SECRET).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_leakwatch"))
        .args(["scan", "--source", "journal", "--machine", "media-01"])
        .arg("--secrets-root")
        .arg(secrets.path())
        .env("PATH", bin.path())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(1),
        "the value sits in the host journal and must be a finding\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("local/leaky"),
        "the finding must point at the host journal: {stdout}"
    );
    assert!(
        !stdout.contains(SECRET),
        "the report must never print the value: {stdout}"
    );
}
