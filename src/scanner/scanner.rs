use super::executor::{self, ExecutionError};
use super::recorder::{RecorderConfig, RecorderError, RecorderHandle, ScanRecorder};
use super::task::Task;
use async_trait::async_trait;
use indicatif::{ProgressBar, ProgressStyle};
use std::fmt::Display;
use std::sync::Arc;
use tokio::sync::mpsc::{self, UnboundedSender};
use tokio::task::JoinHandle;

pub type ScanError = ExecutionError;

#[derive(Debug, Clone)]
pub struct ScanOutput {
    pub target: String,
    pub output: String,
}

pub type ScanResult = Result<Vec<ScanOutput>, ScanError>;

#[derive(Default)]
pub struct ScanOptions {
    pub recorder: Option<RecorderConfig>,
}

struct RecorderRuntime {
    sender: UnboundedSender<(usize, String, String)>,
    forward_handle: JoinHandle<Result<(), RecorderError>>,
    recorder_task: JoinHandle<Result<(), RecorderError>>,
    handle: RecorderHandle,
}

pub struct TargetScanner {
    concurrency: usize,
}

impl TargetScanner {
    pub fn new(concurrency: usize) -> Self {
        Self {
            concurrency: concurrency.max(1),
        }
    }

    pub fn with_default_concurrency() -> Self {
        let threads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        Self::new(threads)
    }

    #[allow(dead_code)]
    pub async fn scan<I, T>(&self, targets: I, task: Arc<T>) -> ScanResult
    where
        I: IntoIterator<Item = String>,
        T: Task + 'static,
        T::Error: Display,
    {
        self.scan_with_options(targets, task, ScanOptions::default())
            .await
    }

    pub async fn scan_with_options<I, T>(
        &self,
        targets: I,
        task: Arc<T>,
        options: ScanOptions,
    ) -> ScanResult
    where
        I: IntoIterator<Item = String>,
        T: Task + 'static,
        T::Error: Display,
    {
        let ScanOptions { recorder } = options;

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

        let mut recorder_runtime = recorder.map(|recorder_cfg| self.spawn_recorder(recorder_cfg));

        let result_sender = recorder_runtime.as_ref().map(|runtime| &runtime.sender);

        let execution_outcome =
            executor::execute(targets_vec, self.concurrency, task, result_sender).await;
        progress_bar.finish_and_clear();

        let recorder_outcome = self.finalize_recorder(recorder_runtime.take()).await;

        match (execution_outcome, recorder_outcome) {
            (Err(err), _) => Err(err),
            (Ok(_), Err(err)) => Err(err),
            (Ok(records), Ok(())) => Ok(records
                .into_iter()
                .map(|(target, output)| ScanOutput { target, output })
                .collect()),
        }
    }

    fn spawn_recorder(&self, recorder_cfg: RecorderConfig) -> RecorderRuntime {
        let base_index = recorder_cfg.base_index;
        let (recorder, handle, receiver) = ScanRecorder::new(recorder_cfg);

        let recorder_handle = handle.clone();
        let recorder_task = tokio::spawn(async move { recorder.run(receiver).await });

        let (sender, receiver) = mpsc::unbounded_channel::<(usize, String, String)>();
        let forward_handle = tokio::spawn(async move {
            let mut receiver = receiver;
            while let Some((index, target, output)) = receiver.recv().await {
                let absolute_index = base_index + index;
                if let Err(err) = recorder_handle.record(absolute_index, target, output) {
                    return Err(err);
                }
            }
            Ok::<_, RecorderError>(())
        });

        RecorderRuntime {
            sender,
            forward_handle,
            recorder_task,
            handle,
        }
    }

    async fn finalize_recorder(&self, runtime: Option<RecorderRuntime>) -> Result<(), ScanError> {
        let Some(runtime) = runtime else {
            return Ok(());
        };

        let RecorderRuntime {
            sender,
            forward_handle,
            recorder_task,
            handle,
        } = runtime;

        // Request a final flush and drop the producer side so the forwarding task can exit.
        let _ = handle.request_flush();
        drop(sender);

        let forward_result = forward_handle.await;
        let recorder_result = recorder_task.await;

        match forward_result {
            Ok(Ok(())) => {}
            Ok(Err(err)) => return Err(ExecutionError::persistence(err)),
            Err(join_err) => return Err(ExecutionError::internal(join_err)),
        }

        match recorder_result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => Err(ExecutionError::persistence(err)),
            Err(join_err) => Err(ExecutionError::internal(join_err)),
        }
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
            Err(_) => {
                // let message = format!("[-] {}: {}", target, err);
                // progress.println(message);
                progress.inc(1);
                Ok(String::new())
            }
        }
    }
}
