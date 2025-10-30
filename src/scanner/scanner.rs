use super::executor::{self, ExecutionError};
use super::task::Task;
use async_trait::async_trait;
use indicatif::{ProgressBar, ProgressStyle};
use std::fmt::Display;
use std::sync::Arc;

pub type ScanError = ExecutionError;

#[derive(Debug, Clone)]
pub struct ScanOutput {
    pub target: String,
    pub output: String,
}

pub type ScanResult = Result<Vec<ScanOutput>, ScanError>;

/// High-level facade that distributes work across a fixed number of asynchronous workers.
///
/// The scanner hands each supplied target to the provided callback while respecting the
/// configured level of parallelism. It is designed to cope with very large target sets without
/// spawning unbounded tasks.
pub struct TargetScanner {
    concurrency: usize,
}

impl TargetScanner {
    /// Create a scanner that executes at most `concurrency` callbacks simultaneously.
    pub fn new(concurrency: usize) -> Self {
        Self {
            concurrency: concurrency.max(1),
        }
    }

    /// Return the configured parallelism level.
    // pub fn concurrency(&self) -> usize {
    //     self.concurrency
    // }

    /// Build a scanner that defaults to the system's advertised parallelism.
    pub fn with_default_concurrency() -> Self {
        let threads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        Self::new(threads)
    }

    /// Scan each target by passing it to the supplied asynchronous callback.
    ///
    /// The callback is awaited before the scanner hands out another target once the concurrency
    /// budget has been reached. The function resolves when every target has been processed.
    pub async fn scan<I, T>(&self, targets: I, task: Arc<T>) -> ScanResult
    where
        I: IntoIterator<Item = String>,
        T: Task + 'static,
        T::Error: Display,
    {
        let targets_vec: Vec<String> = targets.into_iter().collect();
        let total = targets_vec.len() as u64;

        let progress_bar = ProgressBar::new(total);
        progress_bar.set_style(
            ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} ({per_sec} targets/s)")
                .unwrap()
                .progress_chars("##-"),
        );

        let progress_bar_clone = progress_bar.clone();
        let task = Arc::new(ProgressTask {
            inner: Arc::clone(&task),
            progress: progress_bar_clone,
        });

        let results = executor::execute(targets_vec, self.concurrency, task).await;
        progress_bar.finish_and_clear();

        results.map(|records| {
            records
                .into_iter()
                .map(|(target, output)| ScanOutput { target, output })
                .collect()
        })
    }
}

impl Default for TargetScanner {
    fn default() -> Self {
        Self::with_default_concurrency()
    }
}

struct ProgressTask<T: Task> {
    inner: Arc<T>,
    progress: ProgressBar,
}

#[async_trait(?Send)]
impl<T> Task for ProgressTask<T>
where
    T: Task + Send + Sync + 'static,
    T::Error: Display,
{
    type Error = T::Error;

    async fn execute(&self, target: String) -> Result<String, Self::Error> {
        let progress = self.progress.clone();

        match self.inner.execute(target.clone()).await {
            Ok(output) => {
                if !output.trim().is_empty() {
                    progress.println(output.clone());
                }
                progress.inc(1);
                Ok(output)
            }
            Err(err) => {
                let message = format!("[-] {}: {}", target, err);
                progress.println(message);
                progress.inc(1);
                Ok(String::new())
            }
        }
    }
}
