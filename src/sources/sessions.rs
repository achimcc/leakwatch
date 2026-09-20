//! The Claude session transcripts on the workstation — where the five chat
//! leaks actually landed. 1.5 GB in 972 files, so: streamed, never slurped.

use super::Source;
use anyhow::Result;
use std::io::{BufRead, Read};
use std::path::PathBuf;

pub struct Sessions {
    pub root: PathBuf,
}

impl Sessions {
    pub fn files(&self) -> Result<Vec<PathBuf>> {
        let mut out = Vec::new();
        collect(&self.root, &mut out)?;
        Ok(out)
    }
}

fn collect(dir: &std::path::Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(());
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "jsonl") {
            out.push(path);
        }
    }
    Ok(())
}

impl Source for Sessions {
    fn name(&self) -> &str {
        "sessions"
    }
    fn open(&self) -> Result<Box<dyn BufRead>> {
        // Chain every transcript into one stream.
        let files = self.files()?;
        let mut readers: Vec<Box<dyn std::io::Read>> = Vec::new();
        for f in files {
            readers.push(Box::new(std::fs::File::open(f)?));
        }
        let chained = readers.into_iter().fold(
            Box::new(std::io::empty()) as Box<dyn std::io::Read>,
            |acc, r| Box::new(acc.chain(r)),
        );
        Ok(Box::new(std::io::BufReader::new(chained)))
    }
    fn locate(&self, _line: &str) -> (String, String) {
        ("sessions".to_string(), self.root.display().to_string())
    }
}
