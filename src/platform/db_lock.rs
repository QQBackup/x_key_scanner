//! Cross-platform "which processes hold this QQ database open?" probe.
//!
//! This is the login-state probe. While an account is signed in, the QQ main
//! process keeps that account's SQLite databases open (Windows) / holds a
//! POSIX advisory write lock on them (Linux/macOS). Reverse-mapping a file to
//! its holder(s) both proves the account is logged in and recovers the exact
//! QQ pid in one step.
//!
//! * **Windows**: Restart Manager (`rstrtmgr.dll`) enumerates every process in
//!   the session that has the file open. QQ NT keeps `nt_msg.db` (and friends)
//!   open while an account is signed in, so a QQ entry in the holder list is a
//!   login probe that also yields the exact pid. Note the list may contain more
//!   than QQ (e.g. this tool itself while reading the DB) — callers filter by
//!   process name.
//! * **Linux/macOS**: `fcntl(F_GETLK)` reports the pid holding the write lock
//!   in `l_pid`; we never acquire a lock, the probe is strictly read-only.
//!
//! Ported from nt_helper `src/detect/db_lock.rs`.

use std::io;
use std::path::Path;

/// One process holding the database open (Windows) / holding the write lock
/// (Unix). The name is the process/app name as reported by the OS; callers use
/// it to decide whether the holder is a QQ process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbHolder {
    pub pid: u32,
    pub name: String,
}

/// Probe a single database file and return every process holding it open.
///
/// A missing file yields `Ok(vec![])` (nothing holds a file that does not
/// exist); real API failures are returned as errors so callers can skip the
/// file and try the next one.
pub fn probe_db_lock(db_path: &Path) -> io::Result<Vec<DbHolder>> {
    #[cfg(windows)]
    {
        windows::probe_db_lock(db_path)
    }
    #[cfg(not(windows))]
    {
        unix::probe_db_lock(db_path)
    }
}

#[cfg(windows)]
mod windows {
    use super::DbHolder;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use windows_sys::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA,
        ERROR_SESSION_CREDENTIAL_CONFLICT, ERROR_SUCCESS,
    };
    use windows_sys::Win32::System::RestartManager::{
        RmEndSession, RmGetList, RmRegisterResources, RmStartSession, CCH_RM_SESSION_KEY,
        RM_PROCESS_INFO,
    };

    fn decode_wide(buf: &[u16]) -> String {
        let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..len])
    }

    fn describe_err(label: &str, err: u32) -> String {
        let hint = match err {
            ERROR_FILE_NOT_FOUND => " (file missing)".to_string(),
            ERROR_ACCESS_DENIED => {
                " (cannot enumerate holders without permission — if QQ runs \
                 elevated, this tool must too)"
                    .to_string()
            }
            ERROR_SESSION_CREDENTIAL_CONFLICT => {
                " (session credential conflict — cannot enumerate processes in \
                 this session)"
                    .to_string()
            }
            _ => String::new(),
        };
        format!("{label} failed: error=0x{err:X}{hint}")
    }

    pub fn probe_db_lock(db_path: &Path) -> io::Result<Vec<DbHolder>> {
        if !db_path.exists() {
            return Ok(Vec::new());
        }

        let wide: Vec<u16> = db_path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut session_key = [0u16; (CCH_RM_SESSION_KEY + 1) as usize];
        let mut session_handle: u32 = 0;

        // SAFETY: `session_key` is a NUL-terminated 33-WCHAR buffer that
        // outlives the call; `session_handle` is written by the API.
        let start_err = unsafe { RmStartSession(&mut session_handle, 0, session_key.as_mut_ptr()) };
        if start_err != ERROR_SUCCESS {
            return Err(io::Error::other(describe_err("RmStartSession", start_err)));
        }

        struct SessionGuard(u32);
        impl Drop for SessionGuard {
            fn drop(&mut self) {
                // SAFETY: handle came from RmStartSession and is still valid.
                unsafe {
                    let _ = RmEndSession(self.0);
                }
            }
        }
        let _guard = SessionGuard(session_handle);

        let resources = [wide.as_ptr()];
        // SAFETY: `resources` points to one NUL-terminated UTF-16 path that
        // outlives the call; application/service arrays are null.
        let reg_err = unsafe {
            RmRegisterResources(
                session_handle,
                1,
                resources.as_ptr(),
                0,
                std::ptr::null(),
                0,
                std::ptr::null(),
            )
        };
        if reg_err != ERROR_SUCCESS {
            return Err(io::Error::other(describe_err("RmRegisterResources", reg_err)));
        }

        let mut needed: u32 = 0;
        let mut count: u32 = 0;
        let mut reboot_reasons: u32 = 0;
        // SAFETY: null buffer + in/out counts + reboot-reason out param.
        let list_err = unsafe {
            RmGetList(
                session_handle,
                &mut needed,
                &mut count,
                std::ptr::null_mut(),
                &mut reboot_reasons,
            )
        };
        if list_err != ERROR_SUCCESS && list_err != ERROR_MORE_DATA {
            return Err(io::Error::other(describe_err("RmGetList(first)", list_err)));
        }
        if needed == 0 {
            return Ok(Vec::new());
        }

        // The affected-process list can change between the sizing and the fill
        // call; retry a few times when the needed count grows.
        for _ in 0..4 {
            // SAFETY: RM_PROCESS_INFO is plain-old-data; zeroed is a valid
            // initial state that the API fills in before we read it.
            let mut infos = vec![unsafe { std::mem::zeroed::<RM_PROCESS_INFO>() }; needed as usize];
            count = needed;
            let err = unsafe {
                RmGetList(
                    session_handle,
                    &mut needed,
                    &mut count,
                    infos.as_mut_ptr(),
                    &mut reboot_reasons,
                )
            };
            if err == ERROR_SUCCESS {
                let holders = infos
                    .iter()
                    .take(count as usize)
                    .map(|info| DbHolder {
                        pid: info.Process.dwProcessId,
                        name: decode_wide(&info.strAppName),
                    })
                    .collect();
                return Ok(holders);
            }
            if err == ERROR_MORE_DATA && needed > count {
                continue;
            }
            return Err(io::Error::other(describe_err("RmGetList(second)", err)));
        }
        Err(io::Error::other("RmGetList did not converge"))
    }
}

#[cfg(not(windows))]
mod unix {
    use super::DbHolder;
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    pub fn probe_db_lock(db_path: &Path) -> io::Result<Vec<DbHolder>> {
        if !db_path.exists() {
            return Ok(Vec::new());
        }
        let c_path = match std::ffi::CString::new(db_path.as_os_str().as_bytes()) {
            Ok(p) => p,
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "database path contains a NUL byte",
                ))
            }
        };

        // SAFETY: a standard libc fcntl(F_GETLK) probe. We open O_RDONLY without
        // O_CREAT/O_TRUNC so the DB is never mutated, and F_GETLK only reports
        // whether a conflicting lock exists — it acquires nothing. `fl` is a
        // fully zero-initialised `flock` that outlives the call; `fd` is always
        // closed.
        unsafe {
            let fd = libc::open(c_path.as_ptr(), libc::O_RDONLY);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut fl: libc::flock = std::mem::zeroed();
            fl.l_type = libc::F_WRLCK as _;
            fl.l_whence = libc::SEEK_SET as _;
            fl.l_start = 0;
            fl.l_len = 0; // 0 == to EOF, i.e. the whole file
            let rc = libc::fcntl(fd, libc::F_GETLK, &mut fl);
            let err = io::Error::last_os_error();
            libc::close(fd);
            if rc != 0 {
                return Err(err);
            }
            // F_UNLCK means nobody holds a conflicting lock.
            if i32::from(fl.l_type) == libc::F_UNLCK {
                return Ok(Vec::new());
            }
            let pid = fl.l_pid as u32;
            Ok(vec![DbHolder { pid, name: process_name(pid) }])
        }
    }

    /// Best-effort process name for a pid: `/proc/<pid>/comm` on Linux,
    /// `proc_name` on macOS. Empty string when unavailable.
    fn process_name(pid: u32) -> String {
        #[cfg(target_os = "linux")]
        {
            std::fs::read_to_string(format!("/proc/{pid}/comm"))
                .map(|s| s.trim().to_string())
                .unwrap_or_default()
        }
        #[cfg(target_os = "macos")]
        {
            super::super::macos::process_name(pid).unwrap_or_default()
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = pid;
            String::new()
        }
    }
}
