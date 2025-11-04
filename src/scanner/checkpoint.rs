use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};

use tokio::fs;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub next_index: usize,
    pub targets_path: String,
    pub output_path: String,
    pub mode: String,
}

impl Checkpoint {
    pub fn new(
        next_index: usize,
        targets_path: impl Into<String>,
        output_path: impl Into<String>,
        mode: impl Into<String>,
    ) -> Self {
        Self {
            next_index,
            targets_path: targets_path.into(),
            output_path: output_path.into(),
            mode: mode.into(),
        }
    }

    pub fn to_string(&self) -> String {
        format!(
            "next_index={}\ntargets={}\noutput={}\nmode={}\n",
            self.next_index, self.targets_path, self.output_path, self.mode
        )
    }

    pub fn from_str(data: &str) -> Option<Self> {
        let mut values = HashMap::new();
        for line in data.lines() {
            if let Some((key, value)) = line.split_once('=') {
                values.insert(key.trim().to_string(), value.trim().to_string());
            }
        }

        let next_index = values.get("next_index")?.parse().ok()?;
        let targets_path = values.get("targets")?.clone();
        let output_path = values.get("output")?.clone();
        let mode = values.get("mode")?.clone();

        Some(Self {
            next_index,
            targets_path,
            output_path,
            mode,
        })
    }
}

pub async fn write_checkpoint(path: impl AsRef<Path>, checkpoint: &Checkpoint) -> io::Result<()> {
    fs::write(path, checkpoint.to_string()).await
}

pub async fn read_checkpoint(path: impl AsRef<Path>) -> io::Result<Option<Checkpoint>> {
    match fs::read_to_string(&path).await {
        Ok(content) => Ok(Checkpoint::from_str(&content)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

pub async fn remove_checkpoint(path: impl AsRef<Path>) -> io::Result<()> {
    let path_ref = path.as_ref();
    match fs::remove_file(path_ref).await {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

pub fn default_checkpoint_path() -> PathBuf {
    PathBuf::from("checkpoint")
}
