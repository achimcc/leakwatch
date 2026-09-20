//! Log files on disk that never pass through Loki — Caddy's access log,
//! service-owned logs under /var/lib.

use super::Source;
use anyhow::Result;
use std::io::{BufRead, Read};
use std::path::PathBuf;

pub struct Files {
    pub globs: Vec<String>,
}

impl Files {
    /// Resolve the globs. Only `*` inside the last path segment is supported —
    /// that covers every pattern this is used with and needs no dependency.
    pub fn files(&self) -> Result<Vec<PathBuf>> {
        let mut out = Vec::new();
        for pattern in &self.globs {
            let path = std::path::Path::new(pattern);
            let Some(parent) = path.parent() else {
                continue;
            };
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if !name.contains('*') {
                if path.is_file() {
                    out.push(path.to_path_buf());
                }
                continue;
            }
            let (prefix, suffix) = name.split_once('*').expect("contains a star");
            let Ok(entries) = std::fs::read_dir(parent) else {
                continue;
            };
            for entry in entries.flatten() {
                let candidate = entry.file_name().to_string_lossy().to_string();
                if candidate.starts_with(prefix)
                    && candidate.ends_with(suffix)
                    && entry.path().is_file()
                {
                    out.push(entry.path());
                }
            }
        }
        Ok(out)
    }
}

impl Source for Files {
    fn name(&self) -> &str {
        "files"
    }
    fn open(&self) -> Result<Box<dyn BufRead>> {
        let mut readers: Vec<Box<dyn std::io::Read>> = Vec::new();
        for f in self.files()? {
            readers.push(Box::new(std::fs::File::open(f)?));
        }
        let chained = readers.into_iter().fold(
            Box::new(std::io::empty()) as Box<dyn std::io::Read>,
            |acc, r| Box::new(acc.chain(r)),
        );
        Ok(Box::new(std::io::BufReader::new(chained)))
    }
    fn locate(&self, _line: &str) -> (String, String) {
        ("files".to_string(), self.globs.join(","))
    }
}
