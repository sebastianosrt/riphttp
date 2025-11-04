use super::task::Task;
use futures::{StreamExt, stream::FuturesUnordered};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedSender;

#[derive(Debug)]
pub enum ExecutionError {
    TaskFailed { target: String, error: String },
    Persistence { error: String },
    Internal { error: String },
}

impl std::fmt::Display for ExecutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecutionError::TaskFailed { target, error } => {
                write!(f, "task failed for target '{}': {}", target, error)
            }
            ExecutionError::Persistence { error } => {
                write!(f, "failed to persist scan progress: {}", error)
            }
            ExecutionError::Internal { error } => {
                write!(f, "scanner encountered an internal error: {}", error)
            }
        }
    }
}

impl std::error::Error for ExecutionError {}

impl ExecutionError {
    fn task_failed<E: fmt::Display>(target: String, error: E) -> Self {
        Self::TaskFailed {
            target,
            error: error.to_string(),
        }
    }

    pub fn persistence<E: fmt::Display>(error: E) -> Self {
        Self::Persistence {
            error: error.to_string(),
        }
    }

    pub fn internal<E: fmt::Display>(error: E) -> Self {
        Self::Internal {
            error: error.to_string(),
        }
    }
}

type TaskFuture =
    Pin<Box<dyn Future<Output = Result<(usize, String, String), ExecutionError>> + 'static>>;

pub async fn execute<I, T>(
    targets: I,
    concurrency: usize,
    task: Arc<T>,
    result_tx: Option<&UnboundedSender<(usize, String, String)>>,
) -> Result<Vec<(String, String)>, ExecutionError>
where
    I: IntoIterator<Item = String>,
    T: Task + 'static,
    T::Error: fmt::Display,
{
    let mut results = Vec::new();
    let concurrency = concurrency.max(1);
    let mut pending: FuturesUnordered<TaskFuture> = FuturesUnordered::new();
    let mut position: usize = 0;
    let mut iter = targets.into_iter();

    while pending.len() < concurrency {
        if let Some(target) = iter.next() {
            pending.push(schedule_task(Arc::clone(&task), target, position));
            position = position.wrapping_add(1);
        } else {
            break;
        }
    }

    while let Some(result) = pending.next().await {
        match result {
            Ok((index, target, output)) => {
                if let Some(sender) = result_tx {
                    let _ = sender.send((index, target.clone(), output.clone()));
                }

                results.push((index, target, output));

                if let Some(next_target) = iter.next() {
                    pending.push(schedule_task(Arc::clone(&task), next_target, position));
                    position = position.wrapping_add(1);
                }
            }
            Err(err) => return Err(err),
        }
    }

    results.sort_by_key(|(index, _, _)| *index);
    Ok(results
        .into_iter()
        .map(|(_, target, output)| (target, output))
        .collect())
}

fn schedule_task<T>(task: Arc<T>, target: String, index: usize) -> TaskFuture
where
    T: Task + 'static,
    T::Error: fmt::Display,
{
    Box::pin(async move {
        let stored_target = target.clone();
        match task.execute(target).await {
            Ok(output) => Ok((index, stored_target, output)),
            Err(err) => Err(ExecutionError::task_failed(stored_target, err)),
        }
    })
}
