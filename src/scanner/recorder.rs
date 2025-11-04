use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::path::PathBuf;
use std::time::Duration;

use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::time::Interval;

use super::checkpoint::{Checkpoint, default_checkpoint_path, remove_checkpoint, write_checkpoint};
use super::scanner::ScanOutput;

#[derive(Debug, Clone)]
pub struct RecorderConfig {
    pub output_path: PathBuf,
    pub checkpoint_path: PathBuf,
    pub targets_path: String,
    pub mode: String,
    pub base_index: usize,
    pub total_targets: usize,
    pub truncate_output: bool,
    pub flush_interval: Duration,
}

impl RecorderConfig {
    pub fn checkpoint_template(&self, next_index: usize) -> Checkpoint {
        Checkpoint::new(
            next_index,
            self.targets_path.clone(),
            self.output_path.to_string_lossy(),
            self.mode.clone(),
        )
    }
}

#[derive(Debug)]
pub enum RecorderMessage {
    Record {
        absolute_index: usize,
        target: String,
        output: String,
    },
    Flush,
}

#[derive(Clone)]
pub struct RecorderHandle {
    sender: UnboundedSender<RecorderMessage>,
}

impl RecorderHandle {
    pub fn new(sender: UnboundedSender<RecorderMessage>) -> Self {
        Self { sender }
    }

    pub fn record(
        &self,
        absolute_index: usize,
        target: String,
        output: String,
    ) -> Result<(), RecorderError> {
        self.sender
            .send(RecorderMessage::Record {
                absolute_index,
                target,
                output,
            })
            .map_err(|_| RecorderError::ChannelClosed)
    }

    pub fn request_flush(&self) -> Result<(), RecorderError> {
        self.sender
            .send(RecorderMessage::Flush)
            .map_err(|_| RecorderError::ChannelClosed)
    }
}

#[derive(Debug)]
pub enum RecorderError {
    ChannelClosed,
    Io(io::Error),
}

impl From<io::Error> for RecorderError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl fmt::Display for RecorderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecorderError::ChannelClosed => write!(f, "recorder channel closed unexpectedly"),
            RecorderError::Io(err) => write!(f, "{}", err),
        }
    }
}

impl std::error::Error for RecorderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RecorderError::ChannelClosed => None,
            RecorderError::Io(err) => Some(err),
        }
    }
}

struct PendingRecord {
    target: String,
    output: String,
}

pub struct ScanRecorder {
    cfg: RecorderConfig,
    next_expected_index: usize,
    pending: BTreeMap<usize, PendingRecord>,
}

impl ScanRecorder {
    pub fn new(cfg: RecorderConfig) -> (Self, RecorderHandle, UnboundedReceiver<RecorderMessage>) {
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
        let recorder = Self {
            next_expected_index: cfg.base_index,
            cfg,
            pending: BTreeMap::new(),
        };
        let handle = RecorderHandle::new(sender);
        (recorder, handle, receiver)
    }

    async fn open_output(&self) -> io::Result<tokio::fs::File> {
        let mut options = OpenOptions::new();
        options.create(true).write(true);
        if self.cfg.truncate_output {
            options.truncate(true);
        } else {
            options.append(true);
        }
        options.open(&self.cfg.output_path).await
    }

    async fn commit_ready(&mut self, file: &mut tokio::fs::File) -> Result<(), RecorderError> {
        while let Some(record) = self.pending.remove(&self.next_expected_index) {
            let output_entry = ScanOutput {
                target: record.target,
                output: record.output,
            };

            if !output_entry.output.trim().is_empty() {
                file.write_all(output_entry.target.as_bytes()).await?;
                file.write_all(b"\t").await?;
                file.write_all(output_entry.output.as_bytes()).await?;
                file.write_all(b"\n").await?;
            }

            self.next_expected_index += 1;

            let checkpoint = self.cfg.checkpoint_template(self.next_expected_index);
            write_checkpoint(&self.cfg.checkpoint_path, &checkpoint).await?;
        }
        Ok(())
    }

    async fn handle_record(
        &mut self,
        file: &mut tokio::fs::File,
        index: usize,
        target: String,
        output: String,
    ) -> Result<(), RecorderError> {
        if index < self.next_expected_index {
            // Already processed according to checkpoint; skip.
            return Ok(());
        }

        self.pending.insert(index, PendingRecord { target, output });
        self.commit_ready(file).await
    }

    async fn flush_if_due(&mut self, file: &mut tokio::fs::File) -> Result<(), RecorderError> {
        file.flush().await.map_err(RecorderError::from)
    }

    async fn finish(
        mut self,
        mut file: tokio::fs::File,
        mut receiver: UnboundedReceiver<RecorderMessage>,
    ) -> Result<(), RecorderError> {
        let mut flush_timer: Interval = tokio::time::interval(self.cfg.flush_interval);
        loop {
            tokio::select! {
                maybe_message = receiver.recv() => {
                    match maybe_message {
                        Some(RecorderMessage::Record { absolute_index, target, output }) => {
                            self.handle_record(&mut file, absolute_index, target, output).await?;
                        }
                        Some(RecorderMessage::Flush) => {
                            self.flush_if_due(&mut file).await?;
                        }
                        None => {
                            break;
                        }
                    }
                }
                _ = flush_timer.tick() => {
                    self.flush_if_due(&mut file).await?;
                }
            }
        }

        // After channel closed, ensure all pending entries committed.
        self.commit_ready(&mut file).await?;
        self.flush_if_due(&mut file).await?;

        let final_index = self.cfg.base_index + self.cfg.total_targets;

        if self.next_expected_index >= final_index {
            // Completed full run: remove checkpoint file.
            remove_checkpoint(&self.cfg.checkpoint_path).await?;
        }

        Ok(())
    }

    pub async fn run(
        mut self,
        receiver: UnboundedReceiver<RecorderMessage>,
    ) -> Result<(), RecorderError> {
        let mut file = self.open_output().await?;
        self.flush_if_due(&mut file).await?;
        self.finish(file, receiver).await
    }
}

pub fn default_recorder_config(
    output_path: impl Into<PathBuf>,
    targets_path: impl Into<String>,
    mode: impl Into<String>,
    base_index: usize,
    total_targets: usize,
    truncate_output: bool,
) -> RecorderConfig {
    RecorderConfig {
        output_path: output_path.into(),
        checkpoint_path: default_checkpoint_path(),
        targets_path: targets_path.into(),
        mode: mode.into(),
        base_index,
        total_targets,
        truncate_output,
        flush_interval: Duration::from_secs(120),
    }
}
