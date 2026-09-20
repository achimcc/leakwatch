//! The Claude session transcripts on the workstation — where the five chat
//! leaks actually landed. 1.5 GB in 972 files, so: streamed, never slurped.

use super::{LazyFiles, Source};
use anyhow::Result;
use std::io::BufRead;
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
        // Read every transcript as one stream, opening each file lazily —
        // 972 files up front would cost 972 descriptors at once.
        let files = self.files()?;
        Ok(Box::new(std::io::BufReader::new(LazyFiles::new(files))))
    }
    fn locate(&self, _line: &str) -> (String, String) {
        ("sessions".to_string(), self.root.display().to_string())
    }
}
