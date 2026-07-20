//! Non-invasive login-status detection for a specific QQ account.
//!
//! Windows: QQ NT creates a per-account named mutex (keyed by numeric UIN) while
//! signed in. We only *open* it (never create), so probing has no side effect.
//!
//! Linux/macOS: the running client holds an fcntl write lock on the account's
//! `nt_db/nt_msg.db`. We probe read-only with `F_GETLK`, which only queries the
//! lock table and never acquires anything — the exact analog of the open-only
//! mutex probe.
//!
//! Ported from nt_helper `src/detect/login_status.rs`.

use std::path::Path;

/// Probe whether the account is currently logged in on this machine.
///
/// On Windows only `uin` is used; on Unix only `db_dir` (the account's `nt_db`
/// directory) is used. Returns `(logged_in, holder_pid)` — `holder_pid` is the
/// PID holding the lock on Unix (0 / None-equivalent when unknown or Windows).
pub fn is_account_logged_in(uin: &str, db_dir: &Path) -> (bool, Option<u32>) {
    #[cfg(windows)]
    {
        let _ = db_dir;
        (windows_mutex_exists(uin), None)
    }
    #[cfg(not(windows))]
    {
        let _ = uin;
        unix_lock_probe(db_dir)
    }
}

#[cfg(windows)]
fn windows_mutex_exists(uin: &str) -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::OpenMutexW;

    const SYNCHRONIZE: u32 = 0x0010_0000;

    // The literal `//` and trailing `/` are part of the name QQ writes — they are
    // NOT the `Global\` namespace separator and must be preserved exactly.
    let mutex_name = format!("Global//149D051A-54FB-491F-A5AC-20B1E2E226AA/{uin}");
    let wide: Vec<u16> = mutex_name.encode_utf16().chain(std::iter::once(0)).collect();

    // SAFETY: `wide` is a valid NUL-terminated UTF-16 buffer that outlives the
    // call. OpenMutexW only opens an existing object; a returned handle is closed
    // immediately.
    unsafe {
        let handle = OpenMutexW(SYNCHRONIZE, 0, wide.as_ptr());
        if !handle.is_null() {
            CloseHandle(handle);
            true
        } else {
            false
        }
    }
}

#[cfg(not(windows))]
fn unix_lock_probe(db_dir: &Path) -> (bool, Option<u32>) {
    use std::os::unix::ffi::OsStrExt;

    let db = db_dir.join("nt_msg.db");
    if !db.exists() {
        return (false, None);
    }
    let c_path = match std::ffi::CString::new(db.as_os_str().as_bytes()) {
        Ok(p) => p,
        Err(_) => return (false, None),
    };

    // SAFETY: standard libc fcntl(F_GETLK) probe. We open O_RDONLY (no
    // O_CREAT/O_TRUNC) so the DB is never mutated, and F_GETLK only reports
    // whether a conflicting lock exists. `fl` is zero-initialised and outlives
    // the call; `fd` is always closed.
    unsafe {
        let fd = libc::open(c_path.as_ptr(), libc::O_RDONLY);
        if fd < 0 {
            return (false, None);
        }
        let mut fl: libc::flock = std::mem::zeroed();
        fl.l_type = libc::F_WRLCK as _;
        fl.l_whence = libc::SEEK_SET as _;
        fl.l_start = 0;
        fl.l_len = 0; // to EOF
        let rc = libc::fcntl(fd, libc::F_GETLK, &mut fl);
        libc::close(fd);
        if rc != 0 {
            return (false, None);
        }
        let logged_in = i32::from(fl.l_type) != libc::F_UNLCK;
        let pid = if logged_in && fl.l_pid > 0 {
            Some(fl.l_pid as u32)
        } else {
            None
        };
        (logged_in, pid)
    }
}
