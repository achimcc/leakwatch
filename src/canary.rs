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

/// Mix one canary line into a stream, so the whole path — adapter, scanner,
/// formatter — is exercised on real input.
pub fn inject<R: BufRead>(r: R) -> impl BufRead {
    let line = format!("leakwatch-probe {CANARY_VALUE}\n");
    std::io::BufReader::new(std::io::Cursor::new(line.into_bytes()).chain(r))
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
        assert!(!check(&s), "ein Scanner ohne Kanarie darf nicht bestehen");
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
        // Kürzer als MIN_LEN in scan.rs, und die Kontrolle prüfte nichts.
        assert!(CANARY_VALUE.len() >= 16);
    }
}
