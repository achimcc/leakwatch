//! `leakwatch sieve` as a process: values from a temp secrets root, text on
//! stdin, masked text on stdout, the closing line on stderr. A planted value
//! never appears in anything the binary writes.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Output, Stdio};

const VALUE: &str = "planted-secret-value-7f3a9c1e5b2d";

fn root(with_locked: bool) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("arr-apikey"), format!("{VALUE}\n")).unwrap();
    if with_locked {
        let locked = dir.path().join("locked");
        std::fs::write(&locked, "another-value-0123456789abcdef").unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    }
    dir
}

fn run(args: &[&str], input: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_leakwatch"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn text(o: &Output) -> (String, String) {
    (
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

/// An empty secrets root besides the real one: the default roots
/// (/run/secrets) must not be read by the tests, so every call names a
/// `--secrets-root`; on a machine without /run/secrets that is all there is.
fn sieve(dir: &tempfile::TempDir, extra: &[&str], input: &str) -> Output {
    let mut args = vec![
        "sieve",
        "--no-default-roots",
        "--secrets-root",
        dir.path().to_str().unwrap(),
    ];
    args.extend_from_slice(extra);
    run(&args, input)
}

#[test]
fn masks_known_and_guessed_and_prints_summary() {
    let d = root(false);
    let input = format!(
        "GET /api?x=1 X-Api-Key: {VALUE} ok\nAuthorization: Bearer unknown-xyz-123\nplain line\n"
    );
    let o = sieve(&d, &[], &input);
    let (out, err) = text(&o);
    assert!(o.status.success(), "{err}");
    assert!(!out.contains(VALUE) && !err.contains(VALUE));
    assert!(out.contains("<REDACTED:arr-apikey>"), "{out}");
    assert!(out.contains("<REDACTED?:header>"), "{out}");
    assert!(out.contains("plain line"), "{out}");
    assert!(
        err.contains("3 lines") && err.contains("1 known") && err.contains("1 guessed"),
        "{err}"
    );
    assert!(err.contains("secrets loaded"), "{err}");
}

#[test]
fn empty_input_is_fine() {
    let d = root(false);
    let o = sieve(&d, &[], "");
    let (out, err) = text(&o);
    assert!(o.status.success(), "{err}");
    assert!(out.is_empty());
    assert!(err.contains("0 lines"), "{err}");
}

#[test]
fn no_secrets_is_exit_2_without_output() {
    let d = tempfile::tempdir().unwrap();
    let o = sieve(&d, &[], "Authorization: Bearer x\n");
    let (out, err) = text(&o);
    assert_eq!(o.status.code(), Some(2), "{err}");
    assert!(out.is_empty(), "{out}");
    assert!(err.contains("nothing to sieve with"), "{err}");
}

#[test]
fn unreadable_without_allow_partial_is_exit_2() {
    let d = root(true);
    if std::fs::read_to_string(d.path().join("locked")).is_ok() {
        return; // root reads everything
    }
    let o = sieve(&d, &[], &format!("{VALUE}\n"));
    let (out, err) = text(&o);
    assert_eq!(o.status.code(), Some(2), "{err}");
    assert!(out.is_empty(), "{out}");
    assert!(
        err.contains("not readable") && err.contains("--allow-partial"),
        "{err}"
    );
    assert!(!err.contains(VALUE));
}

#[test]
fn allow_partial_prints_and_counts() {
    let d = root(true);
    if std::fs::read_to_string(d.path().join("locked")).is_ok() {
        return;
    }
    let o = sieve(&d, &["--allow-partial"], &format!("{VALUE}\n"));
    let (out, err) = text(&o);
    assert!(o.status.success(), "{err}");
    assert_eq!(out, "<REDACTED:arr-apikey>\n");
    assert!(err.contains("1 unreadable"), "{err}");
}

#[test]
fn no_guess_leaves_bearer() {
    let d = root(false);
    let o = sieve(
        &d,
        &["--no-guess"],
        "Authorization: Bearer unknown-xyz-123\n",
    );
    let (out, _) = text(&o);
    assert_eq!(out, "Authorization: Bearer unknown-xyz-123\n");
}

#[test]
fn help_mentions_sieve() {
    let (out, _) = text(&run(&["--help"], ""));
    assert!(
        out.contains("sieve") && out.contains("--allow-partial"),
        "{out}"
    );
}

/// Review 2026-10-23: a multi-line secret (a wg-quick configuration) is
/// masked by the value of its `PrivateKey = …` line, and the closing line
/// says how many loaded values span several lines.
#[test]
fn wireguard_private_key_is_masked_and_multiline_is_counted() {
    let d = tempfile::tempdir().unwrap();
    std::fs::write(
        d.path().join("vpn-conf"),
        "[Interface]\nPrivateKey = wgPrivateKeyValueLooksLikeBase64ABCDEFGHIJ=\nAddress = 10.2.0.2/32\n",
    )
    .unwrap();
    let o = sieve(
        &d,
        &[],
        "wg: PrivateKey = wgPrivateKeyValueLooksLikeBase64ABCDEFGHIJ= set\nwg: wgPrivateKeyValueLooksLikeBase64ABCDEFGHIJ= alone\n",
    );
    let (out, err) = text(&o);
    assert!(o.status.success(), "{err}");
    assert!(!out.contains("wgPrivateKeyValue"), "{out}");
    assert_eq!(out.matches("<REDACTED:vpn-conf>").count(), 2, "{out}");
    assert!(err.contains("1 multi-line"), "{err}");
}

/// A value the scanner would never search for (shorter than the minimum)
/// must not count as protection: with nothing searchable the sieve refuses,
/// and the closing line always says how many values are actually searched.
#[test]
fn short_values_are_reported_and_alone_refused() {
    let d = tempfile::tempdir().unwrap();
    std::fs::write(d.path().join("tiny"), "ab12\n").unwrap();
    let o = sieve(&d, &[], "x\n");
    let (out, err) = text(&o);
    assert_eq!(o.status.code(), Some(2), "{err}");
    assert!(out.is_empty(), "{out}");
    assert!(err.contains("too short"), "{err}");

    let d = root(false);
    std::fs::write(d.path().join("tiny"), "ab12\n").unwrap();
    let o = sieve(&d, &[], "x\n");
    let (_, err) = text(&o);
    assert!(o.status.success(), "{err}");
    assert!(
        err.contains("2 secrets loaded (1 searched, 1 too short)"),
        "{err}"
    );
}
