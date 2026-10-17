//! Log files on disk that never pass through Loki — Caddy's access log,
//! Squid's cache log, service-owned logs under /var/lib. A guest's files are
//! read from the host under its root (`/var/lib/machines/<guest>/…`), the
//! same way the journal adapter reaches a guest without entering it.
//!
//! EVERY LINE CARRIES ITS FILE. Up to 0.2.3 a finding named the glob
//! (`/var/lib/machines/*/var/log/caddy/*.log`), and "which guest, which
//! file?" was a second round by hand. The reader now prefixes each line with
//! `<path>\t`, and `locate` cuts that prefix back off — the same trick the
//! journal adapter plays with `short-iso` and the unit name. The prefix is a
//! path the caller named, never line content.
//!
//! ROTATED FILES ARE NOT SILENTLY A CLEAN RESULT. `access.log*` matches
//! `access.log.1.gz`; a `.gz` is read through `gzip -dc` (streamed, no
//! temporary file), and a compressed form this adapter cannot read (`.zst`,
//! `.xz`, `.bz2`) is an adapter error naming the file — exit 2, not a
//! shorter window reported as clean. Narrow the glob or decompress.

use super::{Source, spawn_with_stdin};
use anyhow::{Context, Result, bail};
use std::io::{BufRead, Read};
use std::path::{Path, PathBuf};

pub struct Files {
    pub globs: Vec<String>,
}

/// Separator between the file prefix and the line.
const SEP: u8 = b'\t';

/// The longest line read in one piece. A guest's log (or a gzip bomb behind a
/// `.gz`) could otherwise grow one line until memory runs out. The rest of an
/// over-long line is skipped up to its newline; a secret straddling the cut
/// is missed — the price of a bound, and 1 MiB is far beyond any log line.
const MAX_LINE: usize = 1 << 20;

/// The file name as the line prefix, with control characters (`\t`, `\n`,
/// `\r`, …) replaced by `?`. A guest names its own files; a tab or newline
/// in a name would otherwise forge the framing that `file_of` cuts back off.
fn prefix_of(path: &Path) -> Vec<u8> {
    path.to_string_lossy()
        .bytes()
        .map(|b| if b < 0x20 || b == 0x7f { b'?' } else { b })
        .collect()
}

/// Drop the rest of a line that hit [`MAX_LINE`].
fn skip_to_newline(reader: &mut dyn BufRead) -> std::io::Result<()> {
    loop {
        let buf = reader.fill_buf()?;
        if buf.is_empty() {
            return Ok(());
        }
        if let Some(i) = buf.iter().position(|&b| b == b'\n') {
            reader.consume(i + 1);
            return Ok(());
        }
        let n = buf.len();
        reader.consume(n);
    }
}

impl Files {
    /// Resolve the globs. `*` and `?` match within one path segment, `**`
    /// matches any number of directories; a literal segment must exist.
    /// Only regular files come back, sorted, each once.
    pub fn files(&self) -> Result<Vec<PathBuf>> {
        let mut out: Vec<PathBuf> = Vec::new();
        for pattern in &self.globs {
            for p in expand(pattern) {
                if !out.contains(&p) {
                    out.push(p);
                }
            }
        }
        out.sort();
        Ok(out)
    }
}

/// All regular files matching `pattern`.
pub fn expand(pattern: &str) -> Vec<PathBuf> {
    let absolute = pattern.starts_with('/');
    let mut set: Vec<PathBuf> = vec![if absolute {
        PathBuf::from("/")
    } else {
        PathBuf::from(".")
    }];
    let segments: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
    for (i, seg) in segments.iter().enumerate() {
        let last = i + 1 == segments.len();
        let mut next: Vec<PathBuf> = Vec::new();
        for base in &set {
            if *seg == "**" {
                // The directory itself and every directory below it; files
                // are only taken by the segment that follows.
                let mut dirs = Vec::new();
                collect_dirs(base, &mut dirs);
                if last {
                    for d in &dirs {
                        push_files_of(d, "*", &mut next);
                    }
                } else {
                    next.extend(dirs);
                }
            } else if seg.contains(['*', '?']) {
                if last {
                    push_files_of(base, seg, &mut next);
                } else if let Ok(entries) = std::fs::read_dir(base) {
                    for e in entries.flatten() {
                        let name = e.file_name().to_string_lossy().to_string();
                        if wildcard(seg, &name) && is_dir(&e.path()) {
                            next.push(e.path());
                        }
                    }
                }
            } else {
                let p = base.join(seg);
                if (last && is_file(&p)) || (!last && is_dir(&p)) {
                    next.push(p);
                }
            }
        }
        set = next;
        if set.is_empty() {
            break;
        }
    }
    set
}

fn collect_dirs(dir: &Path, out: &mut Vec<PathBuf>) {
    out.push(dir.to_path_buf());
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        // `file_type` does not follow symlinks: a link to a parent would
        // otherwise loop.
        if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            collect_dirs(&e.path(), out);
        }
    }
}

fn push_files_of(dir: &Path, seg: &str, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if wildcard(seg, &name) && is_file(&e.path()) {
            out.push(e.path());
        }
    }
}

/// `*` any run of characters, `?` one character — within one segment.
/// A regular file, NOT through a symbolic link. Guest files are read from the
/// host under the guest's root; a link a guest plants there
/// (`access.log -> /etc/…`) would put a HOST file into the scan — the class
/// of B189 in gast-pruefung. A skipped link loses nothing: a guest that wants
/// to hide its own log can delete it anyway.
fn is_file(p: &Path) -> bool {
    std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_file())
}

/// A directory, not through a symbolic link (same reason as [`is_file`]).
fn is_dir(p: &Path) -> bool {
    std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_dir())
}

pub fn wildcard(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();
    fn go(p: &[char], n: &[char]) -> bool {
        match p.split_first() {
            None => n.is_empty(),
            Some(('*', rest)) => (0..=n.len()).any(|k| go(rest, &n[k..])),
            Some(('?', rest)) => !n.is_empty() && go(rest, &n[1..]),
            Some((c, rest)) => n.first() == Some(c) && go(rest, &n[1..]),
        }
    }
    go(&p, &n)
}

/// How a file is opened, by its suffix.
#[derive(Debug, PartialEq, Eq)]
pub enum Opening {
    Plain,
    Gzip,
    /// A compressed form this adapter does not read — `.zst`, `.xz`, `.bz2`.
    Unreadable(&'static str),
}

pub fn opening(path: &Path) -> Opening {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    if name.ends_with(".gz") {
        Opening::Gzip
    } else if name.ends_with(".zst") {
        Opening::Unreadable("zstd")
    } else if name.ends_with(".xz") {
        Opening::Unreadable("xz")
    } else if name.ends_with(".bz2") {
        Opening::Unreadable("bzip2")
    } else {
        Opening::Plain
    }
}

/// Open `path` for reading without following a symbolic link ANYWHERE in it,
/// and only if it is a regular file — decided on the open descriptor, not on
/// the name. Between expanding the glob and opening, a guest can swap a file
/// for a link or a FIFO; the check in `expand` alone would be a TOCTOU.
/// `openat2(RESOLVE_NO_SYMLINKS)` refuses every link in the path,
/// `O_NONBLOCK` keeps a planted FIFO from blocking the open, and `fstat`
/// decides. Under a unit with `RestrictSUIDSGID=` openat2 is ENOSYS
/// (homeserver caveat `restrictsuidsgid-sperrt-openat2`) — that is an error
/// here, never a fallback to a following open.
pub fn open_nofollow(path: &Path) -> Result<std::fs::File> {
    use rustix::fs::{CWD, Mode, OFlags, ResolveFlags, openat2};
    use rustix::io::Errno;
    let fd = openat2(
        CWD,
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOCTTY | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|e| match e {
        Errno::LOOP | Errno::XDEV => anyhow::anyhow!(
            "{} has a symbolic link in its path — not followed (a guest could point it at a host file)",
            path.display()
        ),
        Errno::NOSYS | Errno::PERM => anyhow::anyhow!(
            "{}: openat2 is not available here ({e}) — refusing to fall back to an open that follows links",
            path.display()
        ),
        other => anyhow::anyhow!("opening {}: {other}", path.display()),
    })?;
    let file = std::fs::File::from(fd);
    let meta = file
        .metadata()
        .with_context(|| format!("fstat {}", path.display()))?;
    if !meta.file_type().is_file() {
        bail!(
            "{} is not a regular file (any more) — not read",
            path.display()
        );
    }
    Ok(file)
}

fn open_one(path: &Path) -> Result<Box<dyn BufRead>> {
    match opening(path) {
        Opening::Plain => {
            let f = open_nofollow(path)?;
            Ok(Box::new(std::io::BufReader::new(f)))
        }
        // gzip reads the descriptor WE opened on stdin; it never sees the path.
        Opening::Gzip => {
            let f = open_nofollow(path)?;
            spawn_with_stdin(&["gzip".to_string(), "-dc".to_string()], f.into())
                .with_context(|| format!("decompressing {}", path.display()))
        }
        Opening::Unreadable(what) => bail!(
            "{} is {what}-compressed and this adapter cannot read it — \
             narrow the glob or decompress it; a skipped file would be a \
             shorter window reported as clean",
            path.display()
        ),
    }
}

/// Reads a list of files as one stream of `<path>\t<line>` lines, opening
/// each file only when the previous one is exhausted.
///
/// WHY LAZY: opening all of them up front costs one descriptor per file,
/// and a systemd unit's default LimitNOFILE is 1024 (see `LazyFiles`).
pub(crate) struct PrefixedFiles {
    rest: std::vec::IntoIter<PathBuf>,
    current: Option<(Vec<u8>, Box<dyn BufRead>)>,
    pending: Vec<u8>,
    pos: usize,
}

impl PrefixedFiles {
    pub(crate) fn new(paths: Vec<PathBuf>) -> Self {
        PrefixedFiles {
            rest: paths.into_iter(),
            current: None,
            pending: Vec::new(),
            pos: 0,
        }
    }

    /// Fill `pending` with the next prefixed line; `false` at the end.
    fn next_line(&mut self) -> std::io::Result<bool> {
        loop {
            if self.current.is_none() {
                let Some(path) = self.rest.next() else {
                    return Ok(false);
                };
                let reader = open_one(&path).map_err(std::io::Error::other)?;
                let mut prefix = prefix_of(&path);
                prefix.push(SEP);
                self.current = Some((prefix, reader));
            }
            let (prefix, reader) = self.current.as_mut().expect("just set above");
            self.pending.clear();
            self.pending.extend_from_slice(prefix);
            let before = self.pending.len();
            let n = reader
                .by_ref()
                .take(MAX_LINE as u64)
                .read_until(b'\n', &mut self.pending)?;
            if n == 0 {
                self.current = None;
                continue;
            }
            if n == MAX_LINE && self.pending.last() != Some(&b'\n') {
                skip_to_newline(reader.as_mut())?;
            }
            if self.pending.last() != Some(&b'\n') {
                self.pending.push(b'\n');
            }
            debug_assert!(self.pending.len() > before);
            self.pos = 0;
            return Ok(true);
        }
    }
}

impl Read for PrefixedFiles {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.pending.len() && !self.next_line()? {
            return Ok(0);
        }
        let n = (self.pending.len() - self.pos).min(buf.len());
        buf[..n].copy_from_slice(&self.pending[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// The file a prefixed line came from, if it carries the prefix.
pub fn file_of(line: &str) -> Option<&str> {
    let (path, _) = line.split_once(SEP as char)?;
    if path.starts_with('/') || path.starts_with("./") {
        Some(path)
    } else {
        None
    }
}

impl Source for Files {
    fn name(&self) -> &str {
        "files"
    }
    fn open(&self) -> Result<Box<dyn BufRead>> {
        let files = self.files()?;
        Ok(Box::new(std::io::BufReader::new(PrefixedFiles::new(files))))
    }
    fn locate(&self, line: &str) -> (String, String) {
        match file_of(line) {
            Some(path) => ("files".to_string(), path.to_string()),
            None => ("files".to_string(), self.globs.join(",")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (p, c) in [
            ("machines/a-01/var/log/caddy/access.log", "a plain\n"),
            ("machines/a-01/var/log/caddy/access.log.1", "a one\n"),
            ("machines/b-02/var/log/caddy/access.log", "b plain\n"),
            ("machines/b-02/var/log/squid/cache.log", "squid\n"),
            ("machines/b-02/var/log/notes.txt", "notes"),
        ] {
            let full = dir.path().join(p);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(full, c).unwrap();
        }
        dir
    }

    fn names(paths: &[PathBuf], root: &Path) -> Vec<String> {
        paths
            .iter()
            .map(|p| p.strip_prefix(root).unwrap().to_string_lossy().to_string())
            .collect()
    }

    #[test]
    fn wildcard_matches_within_a_segment() {
        assert!(wildcard("access.log*", "access.log.1.gz"));
        assert!(wildcard("*.log", "cache.log"));
        assert!(!wildcard("*.log", "cache.log.1"));
        assert!(wildcard("a-0?", "a-01"));
        assert!(!wildcard("a-0?", "a-010"));
        assert!(wildcard("*", ""));
    }

    #[test]
    fn a_star_in_a_middle_segment_fans_out_over_guests() {
        let dir = tree();
        let f = Files {
            globs: vec![format!(
                "{}/machines/*/var/log/caddy/access.log*",
                dir.path().display()
            )],
        };
        let got = names(&f.files().unwrap(), dir.path());
        assert_eq!(
            got,
            vec![
                "machines/a-01/var/log/caddy/access.log",
                "machines/a-01/var/log/caddy/access.log.1",
                "machines/b-02/var/log/caddy/access.log",
            ]
        );
    }

    #[test]
    fn a_double_star_descends_any_depth() {
        let dir = tree();
        let f = Files {
            globs: vec![format!("{}/machines/**/*.log", dir.path().display())],
        };
        let got = names(&f.files().unwrap(), dir.path());
        assert_eq!(
            got,
            vec![
                "machines/a-01/var/log/caddy/access.log",
                "machines/b-02/var/log/caddy/access.log",
                "machines/b-02/var/log/squid/cache.log",
            ]
        );
    }

    #[test]
    fn a_literal_path_and_a_missing_one() {
        let dir = tree();
        let a = format!("{}/machines/b-02/var/log/notes.txt", dir.path().display());
        let f = Files {
            globs: vec![a.clone(), format!("{}/nowhere/*.log", dir.path().display())],
        };
        assert_eq!(f.files().unwrap(), vec![PathBuf::from(a)]);
    }

    #[test]
    fn every_line_carries_its_file_and_locate_cuts_it_back_off() {
        let dir = tree();
        let f = Files {
            globs: vec![format!(
                "{}/machines/*/var/log/caddy/access.log",
                dir.path().display()
            )],
        };
        let mut s = String::new();
        f.open().unwrap().read_to_string(&mut s).unwrap();
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].ends_with("\ta plain"), "{:?}", lines[0]);
        let (source, location) = f.locate(lines[1]);
        assert_eq!(source, "files");
        assert!(
            location.ends_with("machines/b-02/var/log/caddy/access.log"),
            "{location}"
        );
        assert!(
            !location.contains("b plain"),
            "content leaked into the location"
        );
        // A canary line has no prefix: the glob is the fallback.
        let (_, fallback) = f.locate("probe line without a prefix");
        assert!(fallback.contains("access.log"));
    }

    #[test]
    fn a_file_without_a_trailing_newline_still_ends_its_line() {
        let dir = tree();
        let f = Files {
            globs: vec![format!(
                "{}/machines/b-02/var/log/notes.txt",
                dir.path().display()
            )],
        };
        let mut s = String::new();
        f.open().unwrap().read_to_string(&mut s).unwrap();
        assert!(s.ends_with("\tnotes\n"), "{s:?}");
    }

    #[test]
    fn suffixes_decide_how_a_file_is_opened() {
        assert_eq!(opening(Path::new("/x/access.log")), Opening::Plain);
        assert_eq!(opening(Path::new("/x/access.log.1.gz")), Opening::Gzip);
        assert_eq!(
            opening(Path::new("/x/access.log.zst")),
            Opening::Unreadable("zstd")
        );
        assert_eq!(opening(Path::new("/x/a.xz")), Opening::Unreadable("xz"));
        assert_eq!(opening(Path::new("/x/a.bz2")), Opening::Unreadable("bzip2"));
    }

    #[test]
    fn a_gzipped_rotation_is_read_through_gzip() {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("access.log.1");
        std::fs::write(&plain, "canary-in-rotation kX9pQ2mN7vL4\n").unwrap();
        let status = std::process::Command::new("gzip")
            .arg(&plain)
            .status()
            .expect("gzip is available");
        assert!(status.success());
        let f = Files {
            globs: vec![format!("{}/access.log*", dir.path().display())],
        };
        let mut s = String::new();
        f.open().unwrap().read_to_string(&mut s).unwrap();
        assert!(
            s.contains("access.log.1.gz\tcanary-in-rotation kX9pQ2mN7vL4"),
            "{s:?}"
        );
    }

    #[test]
    fn an_unreadable_compression_is_an_error_not_a_skip() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("access.log"), "ok\n").unwrap();
        std::fs::write(dir.path().join("access.log.2.zst"), b"\x28\xb5\x2f\xfd").unwrap();
        let f = Files {
            globs: vec![format!("{}/access.log*", dir.path().display())],
        };
        let mut s = String::new();
        let err = f.open().unwrap().read_to_string(&mut s).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("access.log.2.zst") && msg.contains("zstd"),
            "{msg}"
        );
    }

    #[test]
    fn a_symlink_is_neither_followed_as_file_nor_as_directory() {
        let dir = tempfile::tempdir().unwrap();
        let aussen = tempfile::tempdir().unwrap();
        std::fs::write(aussen.path().join("geheim.log"), "x\n").unwrap();
        std::fs::create_dir(dir.path().join("log")).unwrap();
        std::fs::write(dir.path().join("log/echt.log"), "ok\n").unwrap();
        std::os::unix::fs::symlink(
            aussen.path().join("geheim.log"),
            dir.path().join("log/link.log"),
        )
        .unwrap();
        std::os::unix::fs::symlink(aussen.path(), dir.path().join("verz")).unwrap();
        let root = dir.path().display();
        let f = Files {
            globs: vec![
                format!("{root}/log/*.log"),
                format!("{root}/verz/*.log"),
                format!("{root}/**/*.log"),
            ],
        };
        let got: Vec<String> = f
            .files()
            .unwrap()
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert_eq!(got, vec!["echt.log".to_string()]);
    }

    #[test]
    fn a_file_swapped_for_a_link_after_the_glob_is_refused_at_open() {
        let dir = tempfile::tempdir().unwrap();
        let aussen = tempfile::tempdir().unwrap();
        std::fs::write(aussen.path().join("geheim"), "x\n").unwrap();
        let p = dir.path().join("access.log");
        std::os::unix::fs::symlink(aussen.path().join("geheim"), &p).unwrap();
        let err = open_nofollow(&p).unwrap_err().to_string();
        assert!(err.contains("symbolic link"), "{err}");
        // A link in a directory component, too.
        std::os::unix::fs::symlink(aussen.path(), dir.path().join("verz")).unwrap();
        assert!(open_nofollow(&dir.path().join("verz/geheim")).is_err());
    }

    #[test]
    fn a_fifo_does_not_block_and_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("access.log");
        let ok = std::process::Command::new("mkfifo")
            .arg(&p)
            .status()
            .unwrap();
        assert!(ok.success());
        let err = open_nofollow(&p).unwrap_err().to_string();
        assert!(err.contains("not a regular file"), "{err}");
    }

    #[test]
    fn a_control_character_in_a_file_name_cannot_forge_the_frame() {
        let pre = prefix_of(Path::new("/var/log/a\tb\nc.log"));
        assert_eq!(pre, b"/var/log/a?b?c.log".to_vec());
    }

    #[test]
    fn an_over_long_line_is_cut_and_the_next_line_still_read() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("lang.log");
        let mut inhalt = vec![b'a'; MAX_LINE + 4096];
        inhalt.extend_from_slice(b"\nzweite\n");
        std::fs::write(&p, &inhalt).unwrap();
        let mut r = PrefixedFiles::new(vec![p]);
        let mut s = Vec::new();
        r.read_to_end(&mut s).unwrap();
        let zeilen: Vec<&[u8]> = s.split(|&b| b == b'\n').filter(|z| !z.is_empty()).collect();
        assert_eq!(zeilen.len(), 2);
        assert!(zeilen[0].len() <= MAX_LINE + 300);
        assert!(zeilen[1].ends_with(b"zweite"));
    }
}
