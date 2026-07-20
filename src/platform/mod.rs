//! Platform abstraction for the three privileged operations:
//!   1. find the PID(s) that loaded `wrapper.node` (the QQ NT main process),
//!   2. probe whether a given account is logged in (mutex / fcntl lock),
//!   3. read another process's memory regions.
//!
//! Each OS implements [`ProcessAccess`]; the rest of the app is OS-agnostic.

use std::io;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::PlatformAccess;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::PlatformAccess;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::PlatformAccess;

mod login_status;
pub use login_status::is_account_logged_in;

/// A readable memory region in the target process.
#[derive(Debug, Clone, Copy)]
pub struct MemRegion {
    pub base: usize,
    pub size: usize,
}

/// The three privileged capabilities, implemented per-OS.
pub trait ProcessAccess {
    /// Open a handle/state for reading `pid`'s memory. Returns a descriptive
    /// error (already translated to human-readable guidance) on failure.
    fn open(pid: u32) -> io::Result<Self>
    where
        Self: Sized;

    /// Enumerate the readable, committed memory regions of the target.
    fn regions(&self) -> io::Result<Vec<MemRegion>>;

    /// Read `len` bytes at `addr`. Partial reads are returned as-is; a hard
    /// failure yields an error. Regions that fail to read should be skipped by
    /// the caller, not treated as fatal.
    fn read(&self, addr: usize, len: usize) -> io::Result<Vec<u8>>;
}

/// Find every PID that has `wrapper.node` mapped. The QQ NT main process is the
/// one that loaded this native module; child/renderer processes have not.
pub fn find_wrapper_node_pids() -> io::Result<Vec<u32>> {
    #[cfg(windows)]
    {
        windows::find_wrapper_node_pids()
    }
    #[cfg(target_os = "linux")]
    {
        linux::find_wrapper_node_pids()
    }
    #[cfg(target_os = "macos")]
    {
        macos::find_wrapper_node_pids()
    }
}

/// Whether the current process is running with the privileges needed to read
/// another process's memory (admin on Windows, root on Unix).
pub fn is_elevated() -> bool {
    #[cfg(windows)]
    {
        windows::is_elevated()
    }
    #[cfg(unix)]
    {
        // SAFETY: geteuid is always safe.
        unsafe { libc::geteuid() == 0 }
    }
}

/// One-line, platform-specific hint on how to re-run with privileges.
pub fn elevation_hint() -> &'static str {
    #[cfg(windows)]
    {
        "在管理员终端中重新运行本工具"
    }
    #[cfg(target_os = "macos")]
    {
        "使用 `sudo` 重新运行（内存扫描需要 task_for_pid，macOS 仅授予 root 或已签名的调试器）"
    }
    #[cfg(target_os = "linux")]
    {
        "使用 `sudo` 重新运行（或授予 CAP_SYS_PTRACE），并检查 /proc/sys/kernel/yama/ptrace_scope"
    }
}
