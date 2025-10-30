use std::sync::atomic::{AtomicBool, Ordering};

pub mod core;
pub mod modules;
pub mod scanner;

static VERBOSE: AtomicBool = AtomicBool::new(false);

pub fn is_verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

pub fn set_verbose(verbose: bool) {
    VERBOSE.store(verbose, Ordering::Relaxed);
}
