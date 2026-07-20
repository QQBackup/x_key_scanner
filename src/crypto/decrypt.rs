//! Hand-written SQLCipher v4 page decryption for QQ NT databases.
//!
//! Layout of a QQ NT encrypted DB (page size 4096, confirmed constant across
//! every DB under `nt_db/`):
//!
//! ```text
//! [ 1024-byte QQ wrapper ][ SQLCipher page 1 ][ page 2 ] ...
//!                          ^ salt = first 16 bytes of page 1
//! ```
//!
//! Each page ends with a `reserve` region = IV (16) + page-HMAC digest, rounded
//! up to a 16-byte boundary. Page 1's encrypted data starts *after* the 16-byte
//! salt; later pages have no salt.
//!
//! We deliberately do NOT verify or require the page HMAC to match when merely
//! decrypting — verification is a separate, opt-in step (`verify_key`) used for
//! algorithm/key brute-forcing. This mirrors nt_helper's manual `decrypt.rs`
//! path but without the offset-VFS / sqlcipher machinery.

use crate::crypto::cipher::{Algo, IV_SIZE};

/// QQ NT prepends this many bytes before the real SQLCipher stream.
pub const EXT_HEADER: usize = 1024;
pub const PAGE_SIZE: usize = 4096;
pub const SALT_SIZE: usize = 16;
pub const KEY_SIZE: usize = 32;

/// SQLCipher v4 default KDF iteration count used by QQ NT.
pub const KDF_ITER: u32 = 4000;
/// Fast iteration count SQLCipher uses to derive the per-page HMAC key.
pub const FAST_ITER: u32 = 2;
/// SQLCipher's HMAC-salt mask: the HMAC-key salt = page salt XOR 0x3a.
pub const HMAC_MASK: u8 = 0x3a;

/// Derive the 32-byte AES key from a passphrase + the DB's page-1 salt.
pub fn derive_key(passphrase: &[u8], salt: &[u8], algo: &Algo) -> [u8; KEY_SIZE] {
    let mut key = [0u8; KEY_SIZE];
    algo.pbkdf2(passphrase, salt, KDF_ITER, &mut key);
    key
}

/// Decrypt a single page body given the already-derived AES key.
///
/// `skip` is the number of leading bytes to skip (16 for page 1's salt, else 0).
/// Returns the decrypted data segment (ciphertext region only, HMAC/IV stripped).
fn decrypt_page(page: &[u8], key: &[u8; KEY_SIZE], skip: usize, reserve: usize) -> Option<Vec<u8>> {
    let data_len = PAGE_SIZE - skip;
    let enc_len = data_len.checked_sub(reserve)?;
    let ct = &page[skip..skip + enc_len];
    let iv = &page[skip + enc_len..skip + enc_len + IV_SIZE];
    crate::crypto::cipher::aes256_cbc_decrypt(key, iv, ct)
}

/// Result of probing a (key, algo) pair against a database.
pub struct Verified {
    pub algo: Algo,
}

/// Read the first `EXT_HEADER + PAGE_SIZE` bytes and return page 1 (salt-first).
pub fn read_page1(bytes: &[u8]) -> Option<&[u8]> {
    bytes.get(EXT_HEADER..EXT_HEADER + PAGE_SIZE)
}

/// Verify a (passphrase, algo) guess against page 1.
///
/// The authoritative check is the SQLCipher page HMAC, computed over the page's
/// *ciphertext* (independent of AES decryption) — exactly nt_helper's
/// `verify_key_hmac`. This is why looking for the "SQLite format 3" magic in the
/// decrypted body is wrong: page 1's first 16 plaintext bytes are replaced by
/// the salt, so the decrypted body starts at file offset 16 and never contains
/// the magic.
///
/// When the page HMAC is disabled (`PageHmac::None`) there is nothing to verify
/// on the ciphertext, so we fall back to decrypting page 1 and checking SQLite
/// header invariants that live at/after offset 16.
///
/// Returns the derived AES key on success.
pub fn verify_key(db_bytes: &[u8], passphrase: &[u8], algo: &Algo) -> Option<[u8; KEY_SIZE]> {
    let page1 = read_page1(db_bytes)?;
    let salt = &page1[..SALT_SIZE];
    let key = derive_key(passphrase, salt, algo);

    let hmac_size = algo.page.digest_size();
    if hmac_size == 0 {
        // No page HMAC: decrypt and sanity-check the SQLite header fields that
        // sit just past the salt-occupied first 16 bytes.
        let reserve = algo.page.reserve();
        let body = decrypt_page(page1, &key, SALT_SIZE, reserve)?;
        return sqlite_header_tail_ok(&body).then_some(key);
    }

    // Page-HMAC path: recompute the stored per-page HMAC over the ciphertext.
    let reserve = algo.page.reserve();
    let data_end = PAGE_SIZE - reserve;

    let mut hmac_salt = [0u8; SALT_SIZE];
    for i in 0..SALT_SIZE {
        hmac_salt[i] = page1[i] ^ HMAC_MASK;
    }
    let mut hmac_key = [0u8; KEY_SIZE];
    algo.pbkdf2(&key, &hmac_salt, FAST_ITER, &mut hmac_key);

    let mut hmac_in = Vec::with_capacity(data_end - SALT_SIZE + IV_SIZE + 4);
    hmac_in.extend_from_slice(&page1[SALT_SIZE..data_end]);
    hmac_in.extend_from_slice(&page1[data_end..data_end + IV_SIZE]);
    hmac_in.extend_from_slice(&1u32.to_le_bytes()); // page number, little-endian

    let computed = algo.page_hmac(&hmac_key, &hmac_in);
    let stored = &page1[data_end + IV_SIZE..data_end + IV_SIZE + hmac_size];

    let matches = computed.len() == hmac_size
        && computed.iter().zip(stored).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0;
    matches.then_some(key)
}

/// The decrypted page-1 body starts at file offset 16 (the salt replaces bytes
/// 0..16). Check the fixed SQLite header fields that follow: page size (16..18,
/// big-endian, must be a power of two ≥ 512) and the payload-fraction constants
/// (64/32/32 at offsets 21/22/23 → body 5/6/7).
fn sqlite_header_tail_ok(body: &[u8]) -> bool {
    if body.len() < 8 {
        return false;
    }
    let page_size = u16::from_be_bytes([body[0], body[1]]);
    let page_ok = page_size == 1 /* 65536 sentinel */
        || (page_size >= 512 && page_size.is_power_of_two());
    page_ok && body[5] == 64 && body[6] == 32 && body[7] == 32
}

/// Brute-force the algorithm pair for `db_bytes` given a known `passphrase`.
///
/// Tries all 12 combinations and returns the first that decrypts page 1. The
/// algorithm-detection step must not be skipped: uncommon pairs do occur.
pub fn detect_algo(db_bytes: &[u8], passphrase: &[u8]) -> Option<Verified> {
    Algo::all().find_map(|algo| verify_key(db_bytes, passphrase, &algo).map(|_| Verified { algo }))
}

/// Decrypt an entire QQ NT database to a plaintext SQLite file (in memory).
///
/// `passphrase` is derived per-page via PBKDF2; `algo` must already be known
/// (use [`detect_algo`] first). Page 1 gets a fresh SQLite header written so the
/// output is a standalone, openable SQLite file.
pub fn decrypt_database(db_bytes: &[u8], passphrase: &[u8], algo: &Algo) -> Option<Vec<u8>> {
    if db_bytes.len() <= EXT_HEADER + PAGE_SIZE {
        return None;
    }
    let sc = &db_bytes[EXT_HEADER..];
    let total_pages = sc.len() / PAGE_SIZE;
    let reserve = algo.page.reserve();
    let salt = &sc[..SALT_SIZE];
    let key = derive_key(passphrase, salt, algo);

    let mut out = Vec::with_capacity(total_pages * PAGE_SIZE);
    for page_num in 1..=total_pages {
        let off = (page_num - 1) * PAGE_SIZE;
        let page = &sc[off..off + PAGE_SIZE];
        let skip = if page_num == 1 { SALT_SIZE } else { 0 };
        let dec = decrypt_page(page, &key, skip, reserve)?;

        if page_num == 1 {
            let mut full = vec![0u8; PAGE_SIZE];
            full[..16].copy_from_slice(b"SQLite format 3\0");
            let n = dec.len().min(PAGE_SIZE - 16);
            full[16..16 + n].copy_from_slice(&dec[..n]);
            // Fix page-size field (offset 16..18, big-endian).
            full[16] = (PAGE_SIZE >> 8) as u8;
            full[17] = (PAGE_SIZE & 0xff) as u8;
            out.extend_from_slice(&full);
        } else {
            out.extend_from_slice(&dec);
            let pad = PAGE_SIZE - (out.len() % PAGE_SIZE);
            if pad < PAGE_SIZE {
                out.extend(std::iter::repeat_n(0u8, pad));
            }
        }
    }
    Some(out)
}
