//! Locate QQ NT's data root and the per-account database directories.
//!
//! The data root is where the account folders live:
//!   * Windows: read from `UserDataInfo.ini`, then `<path>/Tencent Files`.
//!   * Linux:   `~/.config/QQ`
//!   * macOS:   `~/Library/Containers/com.tencent.qq/Data/Library/Application Support/QQ`
//!
//! Linux and macOS share an identical directory layout below the root.

use std::path::{Path, PathBuf};

/// The global (account-independent) login database, relative to the data root.
///   * Windows: `nt_qq/global/nt_db/login.db`
///   * Unix:    `global/nt_db/login.db`
pub fn login_db_path(root: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        root.join("nt_qq").join("global").join("nt_db").join("login.db")
    }
    #[cfg(not(windows))]
    {
        root.join("global").join("nt_db").join("login.db")
    }
}

/// The per-account `nt_db` directory holding settings.db, nt_msg.db, etc.
///   * Windows: `<root>/<uin>/nt_qq/nt_db`
///   * Unix:    `<root>/nt_qq_<hash>/nt_db`, hash = md5(md5(uid) + "nt_kernel")
pub fn account_db_dir(root: &Path, uin: &str, uid: &str) -> PathBuf {
    #[cfg(windows)]
    {
        let _ = uid;
        root.join(uin).join("nt_qq").join("nt_db")
    }
    #[cfg(not(windows))]
    {
        let _ = uin;
        root.join(format!("nt_qq_{}", account_hash(uid))).join("nt_db")
    }
}

/// Compute the account folder hash: `md5(md5(uid) + "nt_kernel")`, all lowercase.
#[cfg_attr(windows, allow(dead_code))]
pub fn account_hash(uid: &str) -> String {
    use md5::{Digest, Md5};
    let inner = hex::encode(Md5::digest(uid.as_bytes()));
    let outer = Md5::digest(format!("{inner}nt_kernel").as_bytes());
    hex::encode(outer)
}

/// Detect the QQ data root for the current platform. Returns `None` if it can't
/// be determined (the caller should then fall back to manual input).
pub fn detect_data_root() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        detect_windows_root()
    }
    #[cfg(target_os = "linux")]
    {
        linux_config_qq()
    }
    #[cfg(target_os = "macos")]
    {
        Some(
            home_dir()?
                .join("Library/Containers/com.tencent.qq/Data/Library/Application Support/QQ"),
        )
    }
}

#[cfg(windows)]
fn detect_windows_root() -> Option<PathBuf> {
    const INI: &str = r"C:\Users\Public\Documents\Tencent\QQ\UserDataInfo.ini";
    let text = std::fs::read_to_string(INI).ok()?;
    let mut in_section = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_section = line.eq_ignore_ascii_case("[UserDataSet]");
            continue;
        }
        if in_section {
            // Match the exact key. Note `UserDataSavePathType=...` shares a
            // prefix, so we key on "UserDataSavePath=" (with the '='), and also
            // tolerate stray spaces around it.
            let stripped = line
                .split_once('=')
                .filter(|(k, _)| k.trim().eq_ignore_ascii_case("UserDataSavePath"))
                .map(|(_, v)| v.trim());
            if let Some(val) = stripped {
                if !val.is_empty() {
                    // UserDataSavePath already points AT the data root, which is
                    // the "Tencent Files" folder itself. Only append the folder
                    // if this install's value stops one level short.
                    let p = PathBuf::from(val);
                    if p.file_name().is_some_and(|n| n.eq_ignore_ascii_case("Tencent Files")) {
                        return Some(p);
                    }
                    return Some(p.join("Tencent Files"));
                }
            }
        }
    }
    None
}

#[cfg(unix)]
fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from).filter(|p| !p.as_os_str().is_empty())
}

/// Resolve `~/.config/QQ`, tolerating `sudo`. Under sudo `$HOME` is `/root`,
/// which has no QQ data, so if the direct path is missing we fall back to the
/// invoking user's real home: first `$SUDO_USER`'s home, then any `/home/*` that
/// actually has a `.config/QQ`. We warn when falling back so the user knows we
/// crossed into another account's directory.
#[cfg(target_os = "linux")]
fn linux_config_qq() -> Option<PathBuf> {
    let direct = home_dir().map(|h| h.join(".config").join("QQ"));
    if let Some(p) = &direct {
        if p.exists() {
            return Some(p.clone());
        }
    }

    if let Some(p) = sudo_user_config_qq().or_else(scan_home_config_qq) {
        crate::ui::warn(&format!(
            "当前 HOME 下未找到 .config/QQ（可能是 sudo 运行）；改用 {} 。",
            p.display()
        ));
        return Some(p);
    }

    // Nothing better found; hand back the direct guess so the caller's existing
    // "detected path doesn't exist" flow can prompt for manual input.
    direct
}

/// `$SUDO_USER`'s `~/.config/QQ`, resolved via the passwd database, if present.
#[cfg(target_os = "linux")]
fn sudo_user_config_qq() -> Option<PathBuf> {
    let user = std::env::var_os("SUDO_USER")?;
    let user = user.to_str()?;
    if user.is_empty() || user == "root" {
        return None;
    }
    let candidate = PathBuf::from("/home").join(user).join(".config").join("QQ");
    candidate.exists().then_some(candidate)
}

/// Scan `/home/*/.config/QQ` and return the first that exists.
#[cfg(target_os = "linux")]
fn scan_home_config_qq() -> Option<PathBuf> {
    for entry in std::fs::read_dir("/home").ok()?.flatten() {
        let candidate = entry.path().join(".config").join("QQ");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}
