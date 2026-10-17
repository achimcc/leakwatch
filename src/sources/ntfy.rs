//! ntfy's message cache — every push notification the server delivered, kept
//! by ntfy itself for its cache duration. A secret that went out in a push
//! (an alert text that quotes a URL with a token, a script that sends its
//! own environment) lies there in plain text and passes no journal and no
//! Loki (audit 4, B222).
//!
//! READ THROUGH `sqlite3`, READ-ONLY AND IMMUTABLE. The database belongs to
//! a running ntfy; `mode=ro&immutable=1` opens it without a lock and without
//! the WAL, so the scan can neither block nor change it. A message that is
//! still only in the WAL is missed until ntfy checkpoints — the price of not
//! touching a live database.
//!
//! THE WHOLE CACHE, NOT `--since`. ntfy expires its cache on its own; a
//! window narrower than that would read nothing on a quiet evening and make
//! the source "silent" (exit 2) although it works.
//!
//! One message is one line: `<mid>\t<title>\t<message>\t<click>\t<actions>
//! \t<tags>`, with newlines folded to spaces in SQL. The location of a
//! finding is the database and the message id, never content.
//!
//! NOT THE TOPIC. A topic is ntfy's routing key and stands in every row by
//! construction; scanning it would report each message of a secret topic
//! (measured on the first run, 2026-10-17: 1066 hits, all of them that).
//! Where a topic leaks — Caddy's access log, a journal — the other sources
//! see it.

use super::loki::shell_quote;
use super::{Source, spawn};
use anyhow::Result;
use std::io::BufRead;

pub struct Ntfy {
    /// Path of ntfy's `cache-file` on the machine that runs the query.
    pub db: String,
    pub via_ssh: Option<String>,
}

/// Columns that a publisher fills, each with CR/LF folded to a space.
const SQL: &str = "SELECT mid, replace(replace(title,char(10),' '),char(13),' '), \
replace(replace(message,char(10),' '),char(13),' '), click, \
replace(replace(actions,char(10),' '),char(13),' '), tags FROM messages ORDER BY id";

impl Ntfy {
    pub fn command(&self) -> Vec<String> {
        let uri = format!("file:{}?mode=ro&immutable=1", self.db);
        let sqlite = vec![
            "sqlite3".to_string(),
            "-readonly".to_string(),
            "-batch".to_string(),
            "-noheader".to_string(),
            "-tabs".to_string(),
            uri,
            SQL.to_string(),
        ];
        match &self.via_ssh {
            None => sqlite,
            Some(target) => vec![
                "ssh".to_string(),
                "-o".to_string(),
                "IdentitiesOnly=yes".to_string(),
                target.clone(),
                sqlite
                    .iter()
                    .map(|a| shell_quote(a))
                    .collect::<Vec<_>>()
                    .join(" "),
            ],
        }
    }
}

/// The message id at the start of a line — only `[A-Za-z0-9]`, at most 32
/// characters, so a publisher cannot put anything into a location.
pub fn mid_of(line: &str) -> Option<&str> {
    let (mid, _) = line.split_once('\t')?;
    (!mid.is_empty() && mid.len() <= 32 && mid.bytes().all(|b| b.is_ascii_alphanumeric()))
        .then_some(mid)
}

impl Source for Ntfy {
    fn name(&self) -> &str {
        "ntfy"
    }
    fn open(&self) -> Result<Box<dyn BufRead>> {
        spawn(&self.command())
    }
    fn locate(&self, line: &str) -> (String, String) {
        match mid_of(line) {
            Some(mid) => ("ntfy".to_string(), format!("{}#{mid}", self.db)),
            None => ("ntfy".to_string(), self.db.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_query_opens_the_database_read_only_and_immutable() {
        let n = Ntfy {
            db: "/var/lib/ntfy/cache.db".into(),
            via_ssh: None,
        };
        let c = n.command();
        assert_eq!(c[0], "sqlite3");
        assert!(c.contains(&"-readonly".to_string()));
        assert!(
            c.iter()
                .any(|a| a == "file:/var/lib/ntfy/cache.db?mode=ro&immutable=1")
        );
        assert!(c.last().unwrap().starts_with("SELECT mid, replace("));
        assert!(
            !c.last().unwrap().contains("topic"),
            "the topic is not scanned"
        );
    }

    #[test]
    fn over_ssh_the_whole_command_is_quoted_for_the_remote_shell() {
        let n = Ntfy {
            db: "/x/cache.db".into(),
            via_ssh: Some("root@host".into()),
        };
        let c = n.command();
        assert_eq!(&c[..4], &["ssh", "-o", "IdentitiesOnly=yes", "root@host"]);
        // `&` in the URI and `(`/`'` in the SQL must reach sqlite3 intact.
        assert!(
            c[4].contains("'file:/x/cache.db?mode=ro&immutable=1'"),
            "{}",
            c[4]
        );
        assert!(c[4].contains("char(10),'\\'' '\\''"), "{}", c[4]);
    }

    #[test]
    fn a_location_carries_only_a_clean_message_id() {
        let n = Ntfy {
            db: "/d".into(),
            via_ssh: None,
        };
        assert_eq!(n.locate("AbC123\ttopic\tt\tm").1, "/d#AbC123");
        assert_eq!(n.locate("../etc\ttopic\tt\tm").1, "/d");
        assert_eq!(n.locate("no tab at all").1, "/d");
    }
}
