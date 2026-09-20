//! The positive control. Without it "0 findings" cannot be told apart from
//! "the scanner is broken" — and a silent sensor looks like a quiet day.
//!
//! IT RUNS PER ADAPTER, not once per run: a broken Loki path must not be
//! covered by a healthy journal path.

use crate::scan::Scanner;
use std::io::{BufRead, Read};

pub const CANARY_NAME: &str = "leakwatch-canary";
/// Not a real secret. It exists so a run can prove it is able to find one.
pub const CANARY_VALUE: &str = "leakwatch-canary-4f8a2be71d0c9356";

/// Does this scanner carry the canary at all?
pub fn check(scanner: &Scanner) -> bool {
    !scanner
        .scan_line(&format!("probe {CANARY_VALUE} probe"))
        .is_empty()
}

/// Mix one canary line into a stream, so the scanner and the formatter are
/// exercised on real input.
///
/// WHAT THIS DOES NOT COVER: the canary line comes from memory, chained ahead
/// of the source. A source whose command failed and produced no lines at all
/// still yields a found canary. Proving the SOURCE delivered something is the
/// job of the line count — see [`source_was_silent`].
pub fn inject<R: BufRead>(r: R) -> impl BufRead {
    let line = format!("leakwatch-probe {CANARY_VALUE}\n");
    std::io::BufReader::new(std::io::Cursor::new(line.into_bytes()).chain(r))
}

/// Did the source deliver anything of its own?
///
/// `scan_stream` returns the number of lines it read, and exactly one of those
/// is the canary this module injected. A count of one therefore means the
/// source itself was silent — which, for a command-backed adapter, is a tool
/// failure wearing the costume of a clean result.
pub fn source_was_silent(lines_read: u64) -> bool {
    lines_read <= 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::Scanner;

    fn with_canary() -> Scanner {
        Scanner::new(vec![(CANARY_NAME.into(), CANARY_VALUE.into())]).unwrap()
    }

    #[test]
    fn check_passes_when_the_scanner_can_find_the_canary() {
        assert!(check(&with_canary()));
    }

    #[test]
    fn check_fails_when_the_canary_is_missing_from_the_patterns() {
        let s = Scanner::new(vec![("other".into(), "abc123def456".into())]).unwrap();
        assert!(!check(&s), "a scanner without the canary must not pass");
    }

    #[test]
    fn inject_adds_exactly_one_canary_line_to_a_stream() {
        let data = "a\nb\n";
        let mut out = String::new();
        std::io::Read::read_to_string(&mut inject(data.as_bytes()), &mut out).unwrap();
        assert_eq!(out.matches(CANARY_VALUE).count(), 1);
        assert!(out.contains("a\n"));
        assert!(out.contains("b\n"));
    }

    #[test]
    fn the_canary_is_long_enough_to_be_searched_for() {
        // Shorter than MIN_LEN in scan.rs would make the control check nothing.
        assert!(CANARY_VALUE.len() >= 16);
    }

    #[test]
    fn source_was_silent_when_zero_lines_read() {
        assert!(source_was_silent(0));
    }

    #[test]
    fn source_was_silent_when_only_the_canary_arrived() {
        // Exactly one line — the canary we injected.
        assert!(source_was_silent(1));
    }

    #[test]
    fn source_was_not_silent_when_multiple_lines_read() {
        // At least one line from the source itself.
        assert!(!source_was_silent(2));
    }
}
