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
fn find_anchors(data: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    let n = data.len();
    let mut off = 0;
    while off + 1 + ANCHOR.len() <= n {
        if data[off + 1..off + 1 + ANCHOR.len()] == *ANCHOR {
            out.push(off);
        }
        off += ALIGN;
    }
    out
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
            // Quick reject: no anchor substring at all.
            if !contains_subslice(&data, ANCHOR) {
                return Vec::new();
            }
            let mut found = Vec::new();
            let anchors = find_anchors(&data);
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

/// Naive substring search (regions are large but anchors are rare; this is only
/// a fast pre-filter before the aligned scan).
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}
