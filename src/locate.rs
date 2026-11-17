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

/// Candidate locations for the global login.db, most-preferred first.
///
/// On Linux the file has been seen in two layouts: the usual
/// `global/nt_db/login.db`, and — on some installs — nested under `nt_qq/`
/// like Windows. We return both so the caller can read and merge them,
/// preferring the primary ([`login_db_path`]) on conflict. Other platforms
/// have a single canonical location.
pub fn login_db_candidates(root: &Path) -> Vec<PathBuf> {
    let primary = login_db_path(root);
    #[cfg(target_os = "linux")]
    {
        let alt = root.join("nt_qq").join("global").join("nt_db").join("login.db");
        if alt == primary {
            vec![primary]
        } else {
            vec![primary, alt]
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        vec![primary]
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
    let candidates = detect_data_root_candidates();
    candidates
        .iter()
        .find(|p| p.exists())
        .cloned()
        .or_else(|| candidates.into_iter().next())
}

/// Candidate data roots, most-preferred first.
///
/// Windows can have several (the ini may point elsewhere than the default
/// locations), so callers should take the first that exists rather than
/// trusting a single guess. Other platforms have exactly one.
pub fn detect_data_root_candidates() -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        windows_root_candidates()
    }
    #[cfg(target_os = "linux")]
    {
        linux_config_qq().into_iter().collect()
    }
    #[cfg(target_os = "macos")]
    {
        home_dir()
            .map(|h| {
                vec![
                    h.join("Library/Containers/com.tencent.qq/Data/Library/Application Support/QQ"),
                ]
            })
            .unwrap_or_default()
    }
}

/// What `[UserDataSet]` in `UserDataInfo.ini` says about the data root.
#[cfg(windows)]
struct UserDataInfo {
    /// `UserDataSavePathType`: `2` = honor `UserDataSavePath`, `1` =
    /// `Documents/Tencent Files`, anything else (0, 3, unknown, missing) =
    /// the legacy `Documents/QQ` layout.
    save_path_type: Option<i64>,
    /// `UserDataSavePath` as written, without interpreting the type.
    save_path: Option<String>,
}

/// Parse `%PUBLIC%\Documents\Tencent\QQ\UserDataInfo.ini` (i.e. `Public` next
/// to the user's home). Returns `None` when the file is missing/unreadable.
#[cfg(windows)]
fn read_user_data_info(home: &Path) -> Option<UserDataInfo> {
    let ini = home
        .parent()?
        .join("Public")
        .join("Documents")
        .join("Tencent")
        .join("QQ")
        .join("UserDataInfo.ini");
    let text = std::fs::read_to_string(ini).ok()?;

    let mut info = UserDataInfo { save_path_type: None, save_path: None };
    let mut in_section = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_section = line.eq_ignore_ascii_case("[UserDataSet]");
            continue;
        }
        if !in_section {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else { continue };
        let key = key.trim();
        let value = value.trim();
        if key.eq_ignore_ascii_case("UserDataSavePath") {
            if !value.is_empty() {
                info.save_path = Some(value.to_string());
            }
        } else if key.eq_ignore_ascii_case("UserDataSavePathType") {
            info.save_path_type = value.parse::<i64>().ok();
        }
    }
    Some(info)
}

/// Windows data-root candidates in the order QQ itself would consider them.
///
/// `UserDataSavePathType` decides which directory QQ actually uses:
///   * `2` → `UserDataSavePath` (custom location, e.g. data moved to `D:`)
///   * `1` → `Documents/Tencent Files`
///   * anything else → `Documents/QQ` (legacy NT layout / migrated installs)
///
/// QQ ignores `UserDataSavePath` unless the type is `2`. We still keep it as a
/// lower-priority fallback: users who hand-edit the ini to point back at old
/// data exist, and dropping the path entirely would strand them.
#[cfg(windows)]
fn windows_root_candidates() -> Vec<PathBuf> {
    home_dir().map(|home| windows_root_candidates_for(&home)).unwrap_or_default()
}

/// `windows_root_candidates` with an explicit home — the testable half.
#[cfg(windows)]
fn windows_root_candidates_for(home: &Path) -> Vec<PathBuf> {
    let info = read_user_data_info(home);
    let save_path = info.as_ref().and_then(|i| i.save_path.as_deref()).map(PathBuf::from);
    let save_path_type = info.as_ref().and_then(|i| i.save_path_type);

    let mut roots: Vec<PathBuf> = Vec::new();
    if save_path_type == Some(2) {
        roots.extend(save_path.clone());
    }
    roots.push(if save_path_type == Some(1) {
        home.join("Documents").join("Tencent Files")
    } else {
        home.join("Documents").join("QQ")
    });
    if save_path_type != Some(2) {
        roots.extend(save_path);
    }
    roots.push(home.join("Tencent Files"));
    // Legacy admin profiles nest Documents one level deeper.
    if let Ok(entries) = std::fs::read_dir(home) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !name.to_ascii_lowercase().starts_with("admin") {
                continue;
            }
            let docs = entry.path().join("Documents");
            roots.push(docs.join("Tencent Files"));
            roots.push(docs.join("QQ"));
        }
    }
    roots.dedup();
    roots
}

#[cfg(unix)]
fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from).filter(|p| !p.as_os_str().is_empty())
}

#[cfg(windows)]
fn home_dir() -> Option<PathBuf> {
    std::env::var_os("USERPROFILE").map(PathBuf::from).filter(|p| !p.as_os_str().is_empty())
}

/// Resolve `~/.config/QQ`, tolerating `sudo`. Under sudo `$HOME` is `/root`,
/// whose `.config/QQ` either doesn't exist or is an empty/stale shell with no
/// `login.db`. So we don't trust a bare directory — we require it to actually
/// hold `global/nt_db/login.db`. If the direct path fails that test we fall back
/// to the invoking user's real home: first `$SUDO_USER`'s, then any `/home/*`
/// with a populated QQ dir. We warn when falling back so the user knows we
/// crossed into another account's directory.
#[cfg(target_os = "linux")]
fn linux_config_qq() -> Option<PathBuf> {
    let direct = home_dir().map(|h| h.join(".config").join("QQ"));
    if let Some(p) = &direct {
        if has_login_db(p) {
            return Some(p.clone());
        }
    }

    if let Some(p) = sudo_user_config_qq().or_else(scan_home_config_qq) {
        crate::ui::warn(&format!(
            "当前 HOME 下的 .config/QQ 无 login.db（可能是 sudo 运行）；改用 {} 。",
            p.display()
        ));
        return Some(p);
    }

    // Nothing better found; hand back the direct guess so the caller's existing
    // "detected path doesn't exist" flow can prompt for manual input.
    direct
}

/// Whether `root` is a populated QQ data root, i.e. it holds the login database
/// in either known layout.
#[cfg(target_os = "linux")]
fn has_login_db(root: &Path) -> bool {
    login_db_candidates(root).iter().any(|p| p.exists())
}

/// `$SUDO_USER`'s `~/.config/QQ`, if it holds a login.db.
#[cfg(target_os = "linux")]
fn sudo_user_config_qq() -> Option<PathBuf> {
    let user = std::env::var_os("SUDO_USER")?;
    let user = user.to_str()?;
    if user.is_empty() || user == "root" {
        return None;
    }
    let candidate = PathBuf::from("/home").join(user).join(".config").join("QQ");
    has_login_db(&candidate).then_some(candidate)
}

/// Scan `/home/*/.config/QQ` and return the first that holds a login.db.
#[cfg(target_os = "linux")]
fn scan_home_config_qq() -> Option<PathBuf> {
    for entry in std::fs::read_dir("/home").ok()?.flatten() {
        let candidate = entry.path().join(".config").join("QQ");
        if has_login_db(&candidate) {
            return Some(candidate);
        }
    }
    None
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SEQ: AtomicUsize = AtomicUsize::new(0);

    /// `<tmp>/case-N/home` 加同级的 `<tmp>/case-N/Public/.../UserDataInfo.ini`。
    fn scratch(ini: Option<&str>) -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "xks-locate-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let home = base.join("home");
        std::fs::create_dir_all(&home).unwrap();
        if let Some(text) = ini {
            let dir = base.join("Public/Documents/Tencent/QQ");
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("UserDataInfo.ini"), text).unwrap();
        }
        home
    }

    fn cleanup(home: &Path) {
        if let Some(base) = home.parent() {
            let _ = std::fs::remove_dir_all(base);
        }
    }

    /// `[UserDataSet]` 段 + 给定行，CRLF 换行（QQ 写的就是 CRLF）。
    fn ini(body: &[&str]) -> String {
        let mut lines = vec!["[UserDataSet]"];
        lines.extend_from_slice(body);
        lines.join("\r\n")
    }

    #[test]
    fn save_path_type_2_puts_the_custom_path_first() {
        let home = scratch(Some(&ini(&["UserDataSavePathType=2", r"UserDataSavePath=D:\data"])));
        let roots = windows_root_candidates_for(&home);
        assert_eq!(roots[0], PathBuf::from(r"D:\data"));
        assert!(roots.contains(&home.join("Documents").join("QQ")));
        cleanup(&home);
    }

    #[test]
    fn save_path_type_1_uses_documents_tencent_files() {
        let home = scratch(Some(&ini(&["UserDataSavePathType=1", r"UserDataSavePath=D:\data"])));
        let roots = windows_root_candidates_for(&home);
        assert_eq!(roots[0], home.join("Documents").join("Tencent Files"));
        // QQ 忽略 savePath，但手改 ini 指回旧数据的用户仍要兜住。
        assert!(roots.contains(&PathBuf::from(r"D:\data")));
        cleanup(&home);
    }

    #[test]
    fn other_types_and_missing_type_fall_back_to_documents_qq() {
        for body in [
            vec!["UserDataSavePathType=0", r"UserDataSavePath=D:\data"],
            vec!["UserDataSavePathType=3", r"UserDataSavePath=D:\data"],
            vec![r"UserDataSavePath=D:\data"],
        ] {
            let home = scratch(Some(&ini(&body)));
            let roots = windows_root_candidates_for(&home);
            assert_eq!(roots[0], home.join("Documents").join("QQ"), "ini={body:?}");
            cleanup(&home);
        }
    }

    #[test]
    fn ignores_old_ver_data_path_from_the_import_section() {
        let text = format!(
            "[UserDataImportSet]\r\nOldVerDataPath=D:\\legacy\r\n{}",
            ini(&["UserDataSavePathType=2", r"UserDataSavePath=D:\data"])
        );
        let home = scratch(Some(&text));
        let roots = windows_root_candidates_for(&home);
        assert_eq!(roots[0], PathBuf::from(r"D:\data"));
        assert!(!roots.contains(&PathBuf::from(r"D:\legacy")));
        cleanup(&home);
    }
}
