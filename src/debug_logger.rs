#[cfg(debug_assertions)]
use std::fs::OpenOptions;
#[cfg(debug_assertions)]
use std::io::Write;
#[cfg(debug_assertions)]
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(debug_assertions)]
static LOGGING_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

#[cfg(debug_assertions)]
fn get_log_path() -> Option<std::path::PathBuf> {
    let mut path = std::env::current_exe().ok()?;
    path.pop();
    path.push("debug.txt");
    Some(path)
}

#[cfg(debug_assertions)]
pub fn log_to_file(msg: &str) {
    if LOGGING_IN_PROGRESS.swap(true, Ordering::SeqCst) {
        return;
    }

    struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) {
            LOGGING_IN_PROGRESS.store(false, Ordering::SeqCst);
        }
    }
    let _guard = Guard;

    let path = match get_log_path() {
        Some(p) => p,
        None => return,
    };

    let file = OpenOptions::new().create(true).append(true).open(&path);

    if let Ok(mut f) = file {

        let ticks = unsafe {
            core::ptr::read_volatile(0x7FFE0320u64 as *const u64)
        };

        let _ = writeln!(f, "[T:{:012}] {}", ticks, msg);
        let _ = f.flush();
    }
}

#[cfg(not(debug_assertions))]
#[inline(always)]
pub fn log_to_file(_msg: &str) {}

#[macro_export]
macro_rules! debug_log {
    ($($arg:tt)*) => {

        #[cfg(debug_assertions)]
        {
            $crate::debug_logger::log_to_file(&format!($($arg)*))
        }

        #[cfg(not(debug_assertions))]
        {
            let _ = ();
        }
    };
}

