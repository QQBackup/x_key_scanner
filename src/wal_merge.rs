//! Fold a database's `-wal` sidecar back into the decrypted SQLite image.
//!
//! [`crate::crypto::decrypt_database`] returns the database as it was at its
//! last checkpoint. Everything committed since then lives only in the `-wal`
//! sidecar — and QQ keeps its WAL around for a long time, so "since the last
//! checkpoint" can mean "every message/account added in this session". Decrypt
//! the pages alone and the output is quietly stale: the newest logins are
//! missing from login.db, the newest messages from nt_msg.db.
//!
//! Replaying a WAL by hand means reimplementing a checkpoint: applying frames
//! up to the last commit, growing (or shrinking) the file, then fixing up page
//! 1's change counter, page count and version-valid-for fields. SQLite already
//! does all of that correctly, so we give it both decrypted files in a scratch
//! directory and let it checkpoint for us. Afterwards the image is switched
//! back to rollback-journal mode, so the result is a single self-contained file
//! with no sidecars to keep in sync.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use rusqlite::{Connection, OpenFlags};

use crate::crypto::decrypt::{PAGE_SIZE, WAL_FRAME_HDR_SIZE, WAL_HDR_SIZE};
use crate::crypto::{Algo, decrypt_database, decrypt_wal};

/// A decrypted database, with the result of folding in its `-wal`, if any.
pub struct Decrypted {
    /// A self-contained plaintext SQLite image.
    pub bytes: Vec<u8>,
    /// Frames folded in from the `-wal` sidecar (0 when there was nothing to
    /// merge).
    pub wal_frames: usize,
    /// Why a `-wal` that exists was not merged. The image is then simply the
    /// last checkpoint, i.e. [`decrypt_database`]'s output.
    pub wal_warning: Option<String>,
}

/// Decrypt `db_path` and, when it has one, replay its `-wal` sidecar.
pub fn decrypt_db_file(path: &Path, passphrase: &[u8], algo: &Algo) -> io::Result<Decrypted> {
    let bytes = std::fs::read(path)?;
    decrypt_db_bytes(&bytes, &wal_sidecar(path), passphrase, algo)
}

/// Decrypt an already-read database image, plus the `-wal` sidecar at
/// `wal_path` when it holds something replayable.
pub fn decrypt_db_bytes(
    db_bytes: &[u8],
    wal_path: &Path,
    passphrase: &[u8],
    algo: &Algo,
) -> io::Result<Decrypted> {
    let plain = decrypt_database(db_bytes, passphrase, algo).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "数据库解密失败（算法或密钥不匹配）",
        )
    })?;

    let skip = |warning: Option<String>| Decrypted {
        bytes: plain.clone(),
        wal_frames: 0,
        wal_warning: warning,
    };

    // A zero-length `-wal` is what SQLite leaves behind after a clean
    // checkpoint; there is nothing to replay.
    let wal = match std::fs::read(wal_path) {
        Ok(b) if b.len() > WAL_HDR_SIZE => b,
        Ok(_) => return Ok(skip(None)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(skip(None)),
        Err(e) => return Ok(skip(Some(format!("无法读取 {}：{e}", wal_path.display())))),
    };

    let Some(plain_wal) = decrypt_wal(db_bytes, &wal, passphrase, algo) else {
        return Ok(skip(Some(
            "WAL 头/首页校验不通过（可能来自运行中 QQ 的半截写入）".to_string(),
        )));
    };
    let frames = (plain_wal.len() - WAL_HDR_SIZE) / (WAL_FRAME_HDR_SIZE + PAGE_SIZE);

    match replay(&plain, &plain_wal) {
        Ok(bytes) => Ok(Decrypted {
            bytes,
            wal_frames: frames,
            wal_warning: None,
        }),
        Err(e) => Ok(skip(Some(format!("WAL 回放失败：{e}")))),
    }
}

/// `db_path`'s WAL sidecar: `<db_path>-wal`, as SQLite names it.
pub fn wal_sidecar(db_path: &Path) -> PathBuf {
    let mut os = db_path.as_os_str().to_os_string();
    os.push("-wal");
    PathBuf::from(os)
}

/// Let SQLite replay `wal_plain` into `db_plain` and return the merged image.
fn replay(db_plain: &[u8], wal_plain: &[u8]) -> io::Result<Vec<u8>> {
    let dir = scratch_dir()?;
    let result = replay_in(&dir, db_plain, wal_plain);
    let _ = std::fs::remove_dir_all(&dir);
    result
}

fn replay_in(dir: &Path, db_plain: &[u8], wal_plain: &[u8]) -> io::Result<Vec<u8>> {
    let db = dir.join("merged.db");
    let wal = dir.join("merged.db-wal");
    std::fs::write(&db, db_plain)?;
    std::fs::write(&wal, wal_plain)?;

    let committed_pages = wal_committed_pages(wal_plain);
    {
        // Opening the pair makes SQLite rebuild the wal-index from our log and
        // verify every frame checksum we just computed.
        let conn = Connection::open_with_flags(&db, OpenFlags::SQLITE_OPEN_READ_WRITE)
            .map_err(sqlite_err)?;
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .map_err(sqlite_err)?;

        let pages: i64 = conn
            .query_row("PRAGMA page_count", [], |row| row.get(0))
            .map_err(sqlite_err)?;
        if committed_pages != 0 && pages < i64::from(committed_pages) {
            return Err(io::Error::other(format!(
                "SQLite 只得到 {pages} 页，WAL 最后一个提交却声明 {committed_pages} 页",
            )));
        }

        // Leave rollback-journal mode behind: one self-contained file, no
        // -wal/-shm to keep in sync. Switching modes checkpoints as well.
        let mode: String = conn
            .query_row("PRAGMA journal_mode=DELETE", [], |row| row.get(0))
            .map_err(sqlite_err)?;
        if !mode.eq_ignore_ascii_case("delete") {
            return Err(io::Error::other(format!(
                "SQLite 未能退出 WAL 模式（当前为 {mode}）",
            )));
        }
    }

    if std::fs::metadata(&wal).is_ok_and(|m| m.len() > 0) {
        return Err(io::Error::other("SQLite 未能完整回放 WAL"));
    }
    std::fs::read(&db)
}

/// Page count recorded by the last commit frame of a WAL (0 = no commit).
fn wal_committed_pages(wal_plain: &[u8]) -> u32 {
    let frame_size = WAL_FRAME_HDR_SIZE + PAGE_SIZE;
    let mut pages = 0;
    let mut off = WAL_HDR_SIZE;
    while off + frame_size <= wal_plain.len() {
        let n = u32::from_be_bytes(wal_plain[off + 4..off + 8].try_into().expect("4 bytes"));
        if n != 0 {
            pages = n; // 0 marks a non-commit frame
        }
        off += frame_size;
    }
    pages
}

fn sqlite_err(e: rusqlite::Error) -> io::Error {
    io::Error::other(format!("SQLite: {e}"))
}

/// A private scratch directory for one replay. `tempfile` isn't a dependency
/// (see Cargo.toml), so this mirrors `login_db`'s pid+counter naming — but the
/// directory is created exclusively and owner-only, since plaintext databases
/// (which the tool usually handles as root) live in it for the duration.
fn scratch_dir() -> io::Result<PathBuf> {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    for _ in 0..64 {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut dir = std::env::temp_dir();
        let salt = &n as *const _ as usize;
        dir.push(format!(
            "x_key_scanner_wal_{}_{n}_{salt:x}",
            std::process::id()
        ));
        match create_private_dir(&dir) {
            // A name we didn't pick means someone else planted it (or a stale
            // run still owns it): pick another instead of writing into it.
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
            Ok(()) => return Ok(dir),
        }
    }
    Err(io::Error::other("无法创建临时目录"))
}

#[cfg(unix)]
fn create_private_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new().mode(0o700).create(dir)
}

#[cfg(not(unix))]
fn create_private_dir(dir: &Path) -> io::Result<()> {
    std::fs::create_dir(dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::decrypt::EXT_HEADER;
    use crate::login_db::{PRE_LOGIN_KEY, read_accounts};

    /// `PRAGMA integrity_check` on a decrypted image, in a scratch dir.
    fn integrity(bytes: &[u8]) -> String {
        let dir = scratch_dir().unwrap();
        let p = dir.join("check.db");
        std::fs::write(&p, bytes).unwrap();
        let conn = Connection::open_with_flags(&p, OpenFlags::SQLITE_OPEN_READ_WRITE).unwrap();
        let out: String = conn
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))
            .unwrap();
        drop(conn);
        let _ = std::fs::remove_dir_all(&dir);
        out
    }

    #[test]
    fn real_login_db_merges_its_wal() {
        let p =
            PathBuf::from(std::env::var("HOME").unwrap()).join(".config/QQ/global/nt_db/login.db");
        if !p.exists() {
            return;
        }
        let raw = std::fs::read(&p).unwrap();
        let algo = crate::crypto::detect_algo(&raw, PRE_LOGIN_KEY)
            .unwrap()
            .algo;
        let plain = decrypt_database(&raw, PRE_LOGIN_KEY, &algo).unwrap();

        let merged = decrypt_db_file(&p, PRE_LOGIN_KEY, &algo).unwrap();
        if std::fs::metadata(wal_sidecar(&p)).is_ok_and(|m| m.len() > WAL_HDR_SIZE as u64) {
            assert_eq!(merged.wal_warning, None);
            assert!(merged.wal_frames > 0);
            assert_eq!(integrity(&merged.bytes), "ok");
            assert!(
                merged.bytes.len() >= plain.len(),
                "a checkpoint never shrinks the image"
            );

            // The log has to make a difference: QQ rewrites the misc-data page
            // on every login and keeps it in the WAL.
            let changed = plain
                .chunks(PAGE_SIZE)
                .zip(merged.bytes.chunks(PAGE_SIZE))
                .filter(|(a, b)| a != b)
                .count();
            assert!(changed > 0, "nothing in the image came from the wal");
        }

        let (accounts, detected) = read_accounts(&p).unwrap();
        assert_eq!(detected, algo);
        println!(
            "{} accounts, {} wal frames",
            accounts.len(),
            merged.wal_frames
        );
    }

    /// Real-data check for the layout whose pages live *entirely* in the log:
    /// its main file is a lone page 1, which used to make decryption fail.
    #[test]
    fn real_login_db_with_all_pages_in_the_wal() {
        let p = PathBuf::from(std::env::var("HOME").unwrap())
            .join(".config/QQ/nt_qq/global/nt_db/login.db");
        if !p.exists() {
            return;
        }
        let raw = std::fs::read(&p).unwrap();
        let algo = crate::crypto::detect_algo(&raw, PRE_LOGIN_KEY)
            .unwrap()
            .algo;

        let merged = decrypt_db_file(&p, PRE_LOGIN_KEY, &algo).unwrap();
        assert_eq!(merged.wal_warning, None);
        assert_eq!(integrity(&merged.bytes), "ok");
        if raw.len() == EXT_HEADER + PAGE_SIZE {
            // A lone page 1 in the main file: every data page has to come from
            // the log, and decryption used to bail out on exactly this shape.
            assert!(merged.bytes.len() > EXT_HEADER + PAGE_SIZE);
        }
        // The schema (and everything else) is only reachable through the log.
        let _ = read_accounts(&p).expect("the wal must supply the tables");
    }

    /// Without a sidecar there is nothing to replay, and that is not an error.
    #[test]
    fn missing_wal_sidecar_keeps_the_plain_image() {
        let Some(src) = crate::locate::login_db_candidates(&home())
            .into_iter()
            .find(|p| p.exists())
        else {
            return;
        };
        let raw = std::fs::read(&src).unwrap();
        let algo = crate::crypto::detect_algo(&raw, PRE_LOGIN_KEY)
            .unwrap()
            .algo;
        let plain = decrypt_database(&raw, PRE_LOGIN_KEY, &algo).unwrap();

        let dir = scratch_dir().unwrap();
        let lone = dir.join("login.db"); // no -wal next to it
        std::fs::write(&lone, &raw).unwrap();
        let decrypted = decrypt_db_file(&lone, PRE_LOGIN_KEY, &algo).unwrap();
        assert_eq!(decrypted.wal_frames, 0);
        assert_eq!(decrypted.wal_warning, None);
        assert_eq!(decrypted.bytes, plain);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A WAL copied out of a *running* QQ can end mid-frame or mid-write. The
    /// intact prefix must still replay rather than the whole log being dropped.
    #[test]
    fn torn_wal_keeps_the_intact_prefix() {
        let Some(src) = crate::locate::login_db_candidates(&home())
            .into_iter()
            .find(|p| wal_sidecar(p).exists())
        else {
            return;
        };
        let raw = std::fs::read(&src).unwrap();
        let algo = crate::crypto::detect_algo(&raw, PRE_LOGIN_KEY)
            .unwrap()
            .algo;
        let wal = std::fs::read(wal_sidecar(&src)).unwrap();
        let frame = WAL_FRAME_HDR_SIZE + PAGE_SIZE;
        if (wal.len() - WAL_HDR_SIZE) / frame < 4 {
            return;
        }

        // Half a frame of log left over: the tail frames are simply gone.
        let mut cut = wal.clone();
        cut.truncate(WAL_HDR_SIZE + 3 * frame + 97);
        replay_broken_log(&raw, &cut, &algo, "truncated tail");

        // A page caught mid-write: the checksum chain stops at that frame.
        let mut torn = wal.clone();
        torn[WAL_HDR_SIZE + 3 * frame + 40] ^= 0xff;
        replay_broken_log(&raw, &torn, &algo, "torn frame");
    }

    /// Replay `broken` over `raw` in a scratch dir — in both cases above exactly
    /// the first three frames are intact — and require a healthy image.
    fn replay_broken_log(raw: &[u8], broken: &[u8], algo: &Algo, label: &str) {
        let dir = scratch_dir().unwrap();
        let db = dir.join("live.db");
        std::fs::write(&db, raw).unwrap();
        std::fs::write(wal_sidecar(&db), broken).unwrap();

        let decrypted = decrypt_db_file(&db, PRE_LOGIN_KEY, algo).unwrap();
        assert_eq!(decrypted.wal_warning, None, "{label}");
        assert_eq!(decrypted.wal_frames, 3, "{label}");
        assert_eq!(integrity(&decrypted.bytes), "ok", "{label}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `--output` must land a single self-contained file: no `-wal` sidecar for
    /// whoever opens the result later.
    #[test]
    fn output_image_is_self_contained() {
        let Some(src) = crate::locate::login_db_candidates(&home())
            .into_iter()
            .find(|p| wal_sidecar(p).exists())
        else {
            return;
        };
        let algo = crate::crypto::detect_algo(&std::fs::read(&src).unwrap(), PRE_LOGIN_KEY)
            .unwrap()
            .algo;
        let dir = scratch_dir().unwrap();
        crate::decrypt_login_db(&dir, &src, algo).unwrap();
        assert!(dir.join("login.db").exists());
        assert!(!dir.join("login.db-wal").exists());
        let written = std::fs::read(dir.join("login.db")).unwrap();
        assert_eq!(integrity(&written), "ok");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The QQ data root this test runs against.
    fn home() -> PathBuf {
        let home = PathBuf::from(std::env::var_os("HOME").unwrap_or_default());
        if home.join(".config/QQ").exists() {
            home.join(".config/QQ")
        } else {
            home.join("Library/Containers/com.tencent.qq/Data/Library/Application Support/QQ")
        }
    }
}
