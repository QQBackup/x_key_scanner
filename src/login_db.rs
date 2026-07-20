//! Read the decrypted (plaintext) `login.db` to enumerate cached accounts.
//!
//! By the time we get here the SQLCipher layer has already been stripped by our
//! own AES page decryption ([`crate::crypto::decrypt_database`]), so this is a
//! plain SQLite file. We open it with `rusqlite` (plain `bundled`, no sqlcipher,
//! no openssl) and read `login_table`.
//!
//! `login.db` is account-independent: it lists every account that has signed in
//! on this machine. The interesting columns (numeric string keys in QQ's
//! schema):
//!   "1000" = uin, "1001" = uid, "1007" = user_name (nick).

use std::io;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags};

use crate::crypto::{Algo, decrypt_database, detect_algo};

/// Pre-login passphrase QQ NT bakes into the client, used to decrypt login.db.
const PRE_LOGIN_KEY: &[u8] = b"BD156D6710D54D8782F4";

#[derive(Debug, Clone)]
pub struct Account {
    pub uin: String,
    pub uid: String,
    pub nick: String,
}

/// Decrypt `login.db` at `path` and return the cached accounts.
///
/// Returns the detected algorithm alongside the accounts so callers can reuse it
/// (the same client build tends to use the same pair everywhere).
pub fn read_accounts(path: &Path) -> io::Result<(Vec<Account>, Algo)> {
    let bytes = std::fs::read(path)?;
    let verified = detect_algo(&bytes, PRE_LOGIN_KEY).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "could not decrypt login.db: none of the 12 algorithm pairs matched \
             the built-in pre-login key (client layout may have changed)",
        )
    })?;
    let plain = decrypt_database(&bytes, PRE_LOGIN_KEY, &verified.algo).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "login.db decryption produced no output")
    })?;

    let accounts = query_login_table(&plain)?;
    Ok((accounts, verified.algo))
}

/// Read and merge accounts from several candidate `login.db` locations.
///
/// Some Linux installs keep login.db in a second, Windows-like layout. We read
/// every candidate that exists and merge their accounts, keeping earlier paths
/// authoritative on conflict (same uin). The algorithm is taken from the first
/// path that decrypts. Missing/undecryptable candidates are skipped; an error is
/// only returned if none yield anything.
pub fn read_accounts_merged(paths: &[PathBuf]) -> io::Result<(Vec<Account>, Algo)> {
    let mut merged: Vec<Account> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut algo: Option<Algo> = None;
    let mut last_err: Option<io::Error> = None;

    for path in paths {
        if !path.exists() {
            continue;
        }
        match read_accounts(path) {
            Ok((accounts, a)) => {
                algo.get_or_insert(a);
                for acc in accounts {
                    if seen.insert(acc.uin.clone()) {
                        merged.push(acc);
                    }
                }
            }
            Err(e) => last_err = Some(e),
        }
    }

    match algo {
        Some(a) => Ok((merged, a)),
        None => Err(last_err.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "no login.db candidate could be read")
        })),
    }
}

/// Write the plaintext SQLite image to a temp file and read `login_table`.
fn query_login_table(plain: &[u8]) -> io::Result<Vec<Account>> {
    let tmp = tempfile_path("login");
    std::fs::write(&tmp, plain)?;
    let result = (|| -> rusqlite::Result<Vec<Account>> {
        let conn = Connection::open_with_flags(
            &tmp,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
        )?;
        let mut stmt = conn.prepare(r#"SELECT "1000", "1001", "1007" FROM login_table"#)?;
        let rows = stmt.query_map([], |row| {
            Ok(Account {
                uin: value_to_string(row.get_ref(0)?),
                uid: value_to_string(row.get_ref(1)?),
                nick: value_to_string(row.get_ref(2)?),
            })
        })?;
        Ok(rows.filter_map(Result::ok).collect())
    })();
    let _ = std::fs::remove_file(&tmp);
    result.map_err(|e| io::Error::other(format!("login_table read failed: {e}")))
}

fn value_to_string(v: rusqlite::types::ValueRef<'_>) -> String {
    use rusqlite::types::ValueRef;
    match v {
        ValueRef::Text(t) => String::from_utf8_lossy(t).into_owned(),
        ValueRef::Integer(i) => i.to_string(),
        ValueRef::Real(r) => r.to_string(),
        ValueRef::Blob(b) => String::from_utf8_lossy(b).into_owned(),
        ValueRef::Null => String::new(),
    }
}

/// A unique-ish temp path without pulling in a tempfile crate. Process id +
/// address of a stack local gives enough uniqueness for our single-shot use.
fn tempfile_path(tag: &str) -> std::path::PathBuf {
    let mut dir = std::env::temp_dir();
    let salt = &dir as *const _ as usize;
    dir.push(format!("x_key_scanner_{tag}_{}_{salt:x}.db", std::process::id()));
    dir
}
