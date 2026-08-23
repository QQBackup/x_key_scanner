//! Account-level login detection: reverse-map the account's `nt_msg.db` to the
//! process(es) holding it open, then keep only QQ-named holders.
//!
//! While an account is signed in, the QQ main process keeps a handle / POSIX
//! write lock on the account's `nt_db/nt_msg.db`. Probing exactly that file and
//! filtering the holders by process name tells us both *whether* the account is
//! logged in and *which* pid to scan. One file per account keeps the probe fast
//! even with many cached accounts.

use std::path::Path;

use crate::platform::db_lock::{DbHolder, probe_db_lock};

/// The single database file QQ keeps open per account while signed in.
const LOGIN_DB_FILE: &str = "nt_msg.db";

/// Probe the account's `nt_msg.db` and return the processes holding it open.
///
/// A missing file or a probe error yields an empty list, which the caller
/// treats as "not logged in".
pub fn probe_account_db_holders(db_dir: &Path) -> Vec<DbHolder> {
    probe_db_lock(&db_dir.join(LOGIN_DB_FILE)).unwrap_or_default()
}

/// Whether a process name belongs to QQ NT. The name may be a bare module name
/// (`QQ.exe`), a full path, or the Unix comm (`QQ` / `qq`); we compare the file
/// stem case-insensitively and accept `QQ`-prefixed helpers as well.
pub fn is_qq_process_name(name: &str) -> bool {
    let stem = Path::new(name)
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| name.to_string());
    let stem = stem.to_ascii_lowercase();
    stem == "qq" || stem.starts_with("qq")
}
