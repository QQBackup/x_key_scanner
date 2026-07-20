//! SQLCipher algorithm handling for QQ NT databases.
//!
//! QQ NT databases are SQLCipher v4 streams, but the exact page-HMAC and
//! KDF-HMAC algorithms are NOT fixed across DB types / client versions, so we
//! never hardcode a default — the pair is brute-forced once against a small
//! database (settings.db) and then reused.
//!
//! Everything here is pure RustCrypto: no rusqlite, no openssl. Page decryption
//! (see [`crate::crypto::decrypt`]) is done by hand so we never link a bundled
//! SQLCipher/openssl.

use aes::Aes256;
use aes::cipher::{BlockDecryptMut, KeyIvInit, block_padding::NoPadding};
use cbc::Decryptor;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use sha2::{Sha256, Sha512};

type Aes256CbcDec = Decryptor<Aes256>;

pub const IV_SIZE: usize = 16;
pub const AES_BLOCK: usize = 16;

/// Page-level HMAC algorithm. `None` maps to SQLCipher's `cipher_use_hmac=OFF`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageHmac {
    None,
    Sha1,
    Sha256,
    Sha512,
}

/// KDF (PBKDF2) HMAC algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfHmac {
    Sha1,
    Sha256,
    Sha512,
}

/// A resolved algorithm pair, ready to drive manual page crypto.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Algo {
    pub page: PageHmac,
    pub kdf: KdfHmac,
}

/// Every page-HMAC candidate, in brute-force order.
pub const ALL_PAGE_HMAC: [PageHmac; 4] =
    [PageHmac::None, PageHmac::Sha1, PageHmac::Sha256, PageHmac::Sha512];
/// Every KDF-HMAC candidate, in brute-force order.
pub const ALL_KDF_HMAC: [KdfHmac; 3] = [KdfHmac::Sha1, KdfHmac::Sha256, KdfHmac::Sha512];

impl PageHmac {
    pub fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }

    /// Size of the per-page HMAC digest in bytes (0 when HMAC is off).
    pub fn digest_size(self) -> usize {
        match self {
            Self::None => 0,
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }

    /// Per-page reserve = IV + HMAC digest, rounded up to the AES block size.
    pub fn reserve(self) -> usize {
        (IV_SIZE + self.digest_size()).div_ceil(AES_BLOCK) * AES_BLOCK
    }
}

impl KdfHmac {
    pub fn label(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }
}

impl Algo {
    /// Iterate over all 12 algorithm combinations in brute-force order.
    pub fn all() -> impl Iterator<Item = Algo> {
        ALL_PAGE_HMAC
            .into_iter()
            .flat_map(|page| ALL_KDF_HMAC.into_iter().map(move |kdf| Algo { page, kdf }))
    }

    /// PBKDF2 with the configured KDF-HMAC, filling `out`.
    pub fn pbkdf2(&self, pass: &[u8], salt: &[u8], iter: u32, out: &mut [u8]) {
        match self.kdf {
            KdfHmac::Sha1 => pbkdf2_hmac::<Sha1>(pass, salt, iter, out),
            KdfHmac::Sha256 => pbkdf2_hmac::<Sha256>(pass, salt, iter, out),
            KdfHmac::Sha512 => pbkdf2_hmac::<Sha512>(pass, salt, iter, out),
        }
    }

    /// Compute the page-level HMAC over `data`. Empty vec when page HMAC is None.
    pub fn page_hmac(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        macro_rules! mac {
            ($t:ty) => {{
                let mut m = Hmac::<$t>::new_from_slice(key).expect("HMAC accepts any key length");
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }};
        }
        match self.page {
            PageHmac::None => Vec::new(),
            PageHmac::Sha1 => mac!(Sha1),
            PageHmac::Sha256 => mac!(Sha256),
            PageHmac::Sha512 => mac!(Sha512),
        }
    }
}

/// Decrypt one AES-256-CBC block region in place, returning the plaintext.
///
/// `iv` must be 16 bytes; `ciphertext` a multiple of 16. No padding is applied
/// (SQLCipher pages are block-aligned).
pub fn aes256_cbc_decrypt(key: &[u8; 32], iv: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
    let iv: &[u8; IV_SIZE] = iv.try_into().ok()?;
    let cipher = Aes256CbcDec::new(key.into(), iv.into());
    let mut buf = ciphertext.to_vec();
    cipher.decrypt_padded_mut::<NoPadding>(&mut buf).ok()?;
    Some(buf)
}
