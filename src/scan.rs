//! Memory scanner: find the NTQQ raw master key by anchoring on the SQLCipher
//! HMAC-algorithm marker the client keeps next to the key in memory.
//!
//! Ported from the reference `extract_key.py`. The anchor is the byte sequence
//! `\x09HMAC_SHA1` (a length-prefixed "HMAC_SHA1" string). Near each 16-byte
//! aligned anchor, within ±RADIUS, we look for a 16-byte aligned window that
//! looks like a key: all printable, but NOT all alphanumeric (which would just
//! be an ordinary string). The nearest such window is the raw_key candidate.
//!
//! Native builds (Windows/macOS) keep the key inside the SQLCipher codec struct,
//! right next to its HMAC_SHA1 marker, so the per-anchor search finds it. Electron
//! builds (Linux QQ) hold the key as a V8 string on the JS heap, far (often 100s
//! of KB) from any single anchor — the per-anchor search misses it there. But the
//! codec contexts still cluster: many HMAC_SHA1 markers pack into one dense band,
//! and the live key sits near that band's center. So we also collect candidates by
//! walking outward from the densest anchor cluster's center. Both candidate sets
//! are merged; downstream settings.db verification filters false positives, so the
//! extra candidates can never yield a wrong key.
//!
//! Regions are scanned in parallel with rayon to shrink the time window during
//! which a live QQ can mutate the key material.

use std::collections::HashMap;

use rayon::prelude::*;

use crate::platform::ProcessAccess;

/// `\x09HMAC_SHA1` — length-prefixed marker sitting next to the key.
const ANCHOR: &[u8] = &[0x09, b'H', b'M', b'A', b'C', b'_', b'S', b'H', b'A', b'1'];
const ALIGN: usize = 16;
const RADIUS: usize = 0x200;
const KEY_LEN: usize = 16;
/// Cap per-region read size so a pathological giant region can't OOM us.
const MAX_REGION: usize = 512 * 1024 * 1024;
/// Anchors closer than this belong to the same cluster (codec-context band).
const CLUSTER_GAP: usize = 0x4000;
/// A cluster must hold at least this many anchors to be trusted as a codec band
/// (a lone stray anchor points at unrelated strings, e.g. `internal/cluster`).
const MIN_CLUSTER_ANCHORS: usize = 4;
/// How far to walk outward from a cluster center before giving up.
const CLUSTER_MAX_OUT: usize = 0x20000;
/// Collect at most this many key candidates per cluster (the nearest few).
const CLUSTER_KEYS_PER: usize = 4;

fn is_printable(b: u8) -> bool {
    (0x20..0x7f).contains(&b)
}
fn is_alnum(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

/// A 16-byte window qualifies as a key candidate iff every byte is printable and
/// they are not *all* alphanumeric (ordinary text is rejected).
fn key_ok(win: &[u8]) -> bool {
    win.len() == KEY_LEN
        && win.iter().all(|&b| is_printable(b))
        && !win.iter().all(|&b| is_alnum(b))
}

/// Find 16-byte-aligned slots whose *next* byte begins the anchor (matching the
/// python `data[off+1:off+11] == FIXED`): the `\x09` length-prefix sits at
/// `off+1`, so "HMAC_SHA1" itself is what lands on the aligned boundary + 2.
/// Returns the aligned slot `off` (used as the search center for `nearest_key`).
///
/// The anchor is rare, so we let memchr's SIMD substring search jump straight to
/// each occurrence instead of testing every 16-byte slot; a hit at `p` maps to
/// the aligned slot `p - 1`, kept only when that slot is ALIGN-aligned.
fn find_anchors(data: &[u8]) -> Vec<usize> {
    memchr::memmem::find_iter(data, ANCHOR)
        .filter_map(|p| p.checked_sub(1).filter(|off| off % ALIGN == 0))
        .collect()
}

/// Nearest aligned key window to `anchor`, searching outward in ALIGN steps up
/// to RADIUS. Returns the window bytes.
fn nearest_key(data: &[u8], anchor: usize) -> Option<[u8; KEY_LEN]> {
    let n = data.len();
    let a16 = (anchor / ALIGN) * ALIGN;
    let mut step = 0usize;
    while step <= RADIUS {
        let mut cands = [a16.checked_sub(step), a16.checked_add(step)];
        if step == 0 {
            cands[1] = None;
        }
        for cand in cands.into_iter().flatten() {
            if cand + KEY_LEN <= n && key_ok(&data[cand..cand + KEY_LEN]) {
                let mut w = [0u8; KEY_LEN];
                w.copy_from_slice(&data[cand..cand + KEY_LEN]);
                return Some(w);
            }
        }
        step += ALIGN;
    }
    None
}

/// Read a KEY_LEN window at `off` if it qualifies as a key candidate.
fn key_at(data: &[u8], off: usize) -> Option<[u8; KEY_LEN]> {
    if off + KEY_LEN <= data.len() && key_ok(&data[off..off + KEY_LEN]) {
        let mut w = [0u8; KEY_LEN];
        w.copy_from_slice(&data[off..off + KEY_LEN]);
        Some(w)
    } else {
        None
    }
}

/// Group sorted anchor offsets into clusters, splitting wherever two consecutive
/// anchors are farther apart than CLUSTER_GAP. Each cluster is a contiguous band
/// of codec contexts.
fn cluster_anchors(anchors: &[usize]) -> Vec<&[usize]> {
    let mut clusters = Vec::new();
    if anchors.is_empty() {
        return clusters;
    }
    let mut start = 0;
    for i in 1..anchors.len() {
        if anchors[i] - anchors[i - 1] > CLUSTER_GAP {
            clusters.push(&anchors[start..i]);
            start = i;
        }
    }
    clusters.push(&anchors[start..]);
    clusters
}

/// From the densest anchor cluster, walk outward from its center in ALIGN steps
/// and collect up to CLUSTER_KEYS_PER key candidates. This recovers the Electron
/// key, which lives near the codec band's center rather than beside any single
/// anchor. Small clusters (below MIN_CLUSTER_ANCHORS) are ignored as noise.
fn cluster_keys(data: &[u8], anchors: &[usize]) -> Vec<[u8; KEY_LEN]> {
    let clusters = cluster_anchors(anchors);
    let Some(best) = clusters
        .into_iter()
        .filter(|c| c.len() >= MIN_CLUSTER_ANCHORS)
        .max_by_key(|c| c.len())
    else {
        return Vec::new();
    };

    let center = (best[0] + best[best.len() - 1]) / 2;
    let c16 = (center / ALIGN) * ALIGN;

    let mut found = Vec::new();
    let mut step = 0usize;
    while step <= CLUSTER_MAX_OUT && found.len() < CLUSTER_KEYS_PER {
        let mut cands = [c16.checked_sub(step), c16.checked_add(step)];
        if step == 0 {
            cands[1] = None;
        }
        for cand in cands.into_iter().flatten() {
            if let Some(k) = key_at(data, cand) {
                if !found.contains(&k) {
                    found.push(k);
                }
            }
        }
        step += ALIGN;
    }
    found
}

/// A raw_key candidate and how many times it was seen across regions.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub key: [u8; KEY_LEN],
    pub count: usize,
}

/// Scan the process's readable regions for raw_key candidates, ranked by how
/// often each was found (most frequent first).
pub fn scan<A: ProcessAccess + Sync>(access: &A) -> std::io::Result<Vec<Candidate>> {
    let regions = access.regions()?;

    // Each region independently yields a list of candidate keys; merge after.
    let per_region: Vec<Vec<[u8; KEY_LEN]>> = regions
        .par_iter()
        .map(|region| {
            let size = region.size.min(MAX_REGION);
            let data = match access.read(region.base, size) {
                Ok(d) => d,
                Err(_) => return Vec::new(), // unreadable region: skip, not fatal
            };
            // Quick reject: no anchor at all (memmem's SIMD scan returns empty).
            let anchors = find_anchors(&data);
            if anchors.is_empty() {
                return Vec::new();
            }
            let mut found = Vec::new();
            // Native path: key sits beside a single anchor.
            for &anchor in &anchors {
                if let Some(k) = nearest_key(&data, anchor) {
                    found.push(k);
                }
            }
            // Electron fallback: key sits near the densest cluster's center.
            found.extend(cluster_keys(&data, &anchors));
            found
        })
        .collect();

    let mut counts: HashMap<[u8; KEY_LEN], usize> = HashMap::new();
    for keys in per_region {
        for k in keys {
            *counts.entry(k).or_insert(0) += 1;
        }
    }

    let mut cands: Vec<Candidate> =
        counts.into_iter().map(|(key, count)| Candidate { key, count }).collect();
    cands.sort_by_key(|c| std::cmp::Reverse(c.count));
    Ok(cands)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::MemRegion;

    /// In-memory fake process backed by a single byte buffer at `base`.
    struct FakeAccess {
        base: usize,
        data: Vec<u8>,
    }

    impl ProcessAccess for FakeAccess {
        fn open(_pid: u32) -> std::io::Result<Self> {
            unreachable!("FakeAccess is constructed directly in tests")
        }
        fn regions(&self) -> std::io::Result<Vec<MemRegion>> {
            Ok(vec![MemRegion { base: self.base, size: self.data.len() }])
        }
        fn read(&self, addr: usize, len: usize) -> std::io::Result<Vec<u8>> {
            let off = addr - self.base;
            Ok(self.data[off..(off + len).min(self.data.len())].to_vec())
        }
    }

    /// Write the length-prefixed `\x09HMAC_SHA1` marker so its aligned slot passes
    /// `find_anchors` (which matches the anchor at slot+1).
    fn put_anchor(buf: &mut [u8], slot: usize) {
        buf[slot] = 0x00; // any non-anchor byte; the `\x09` prefix lands at slot+1
        buf[slot + 1..slot + 1 + ANCHOR.len()].copy_from_slice(ANCHOR);
    }

    #[test]
    fn native_layout_key_beside_single_anchor() {
        // Key within RADIUS of one anchor — the original per-anchor path. Fill with
        // 0x00 (non-printable) so the only key_ok window is the one we plant.
        let mut buf = vec![0x00u8; 0x1000];
        let anchor = 0x800;
        put_anchor(&mut buf, anchor);
        let key = *b"nativeKEY!@#$%^&"; // 16 bytes, printable, not all-alnum
        buf[anchor + 0x100..anchor + 0x100 + KEY_LEN].copy_from_slice(&key);

        let acc = FakeAccess { base: 0x10000, data: buf };
        let cands = scan(&acc).unwrap();
        assert!(cands.iter().any(|c| c.key == key), "native key must be found");
    }

    #[test]
    fn electron_layout_key_near_cluster_center_only() {
        // Reproduce the Linux/Electron shape and prove the cluster path is doing the
        // work: BOTH the real key and the decoy sit farther than RADIUS from every
        // anchor, so the per-anchor path finds neither. The real key is near the
        // dense cluster's center (reachable by cluster_keys); the decoy hugs a lone
        // stray anchor whose size-1 cluster is filtered by MIN_CLUSTER_ANCHORS and
        // lies beyond CLUSTER_MAX_OUT of the real cluster — so it must never appear.
        let mut buf = vec![0x00u8; 0x50000];

        // Dense cluster: anchors spaced 0x200 (< CLUSTER_GAP) near the start.
        let cluster_start = 0x2000;
        let n_anchors = MIN_CLUSTER_ANCHORS + 4;
        for i in 0..n_anchors {
            put_anchor(&mut buf, cluster_start + i * 0x200);
        }
        let cluster_end = cluster_start + (n_anchors - 1) * 0x200;

        // Real key: just past the cluster's high end, RADIUS*2 from the nearest
        // anchor (so the per-anchor path can't reach it) but well within
        // CLUSTER_MAX_OUT of the center (so cluster_keys can).
        let real = *b"gWDxEK)azQqFNBD<"; // 16 bytes, printable, not all-alnum
        let key_pos = cluster_end + 2 * RADIUS;
        buf[key_pos..key_pos + KEY_LEN].copy_from_slice(&real);

        // Lone stray anchor with a decoy key 2*RADIUS away: unreachable by the
        // per-anchor path, its cluster too small to trust, and beyond the real
        // cluster's outward reach.
        let stray = 0x40000;
        put_anchor(&mut buf, stray);
        let decoy = *b"decoyKEY{}|~<>?/";
        let decoy_pos = stray + 2 * RADIUS;
        buf[decoy_pos..decoy_pos + KEY_LEN].copy_from_slice(&decoy);

        let acc = FakeAccess { base: 0x100000, data: buf };
        let cands = scan(&acc).unwrap();

        assert!(
            cands.iter().any(|c| c.key == real),
            "cluster-center path must recover the Electron key"
        );
        assert!(
            !cands.iter().any(|c| c.key == decoy),
            "stray single-anchor cluster must be ignored (decoy leaked)"
        );
    }

    #[test]
    fn cluster_split_respects_gap() {
        // Two anchor groups separated by more than CLUSTER_GAP form two clusters.
        let anchors = vec![0x1000, 0x1200, 0x1400, 0x1000 + CLUSTER_GAP + 0x8000];
        let clusters = cluster_anchors(&anchors);
        assert_eq!(clusters.len(), 2);
        assert_eq!(clusters[0].len(), 3);
        assert_eq!(clusters[1].len(), 1);
    }
}
