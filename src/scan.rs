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
//!
//! The default (`Mode::Normal`) pass stops there. `Mode::Strong` additionally
//! sweeps the whole region outward from the anchor band, testing every aligned
//! window against settings.db and stopping the instant a candidate verifies.
//! It trades time for robustness when the key has drifted far from the anchors.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use indicatif::ProgressBar;
use rayon::prelude::*;

use crate::platform::{MemRegion, ProcessAccess};

/// `\x09HMAC_SHA1` — length-prefixed marker sitting next to the key.
const ANCHOR: &[u8] = &[0x09, b'H', b'M', b'A', b'C', b'_', b'S', b'H', b'A', b'1'];
const ALIGN: usize = 16;
const RADIUS: usize = 0x200;
const KEY_LEN: usize = 16;
/// Cap per-region read size so a pathological giant region can't OOM us.
const MAX_REGION: usize = 512 * 1024 * 1024;
/// Strong mode keeps at most this many candidates per region before giving up:
/// a last-resort guard so a heap full of printable strings can't exhaust RAM.
const STRONG_MAX_CANDIDATES: usize = 200_000;
/// Strong mode verifies candidates in batches of this size so a wide outward
/// sweep still uses every core (each verification is a PBKDF2 brute-force).
const STRONG_VERIFY_BATCH: usize = 256;
/// Anchors closer than this belong to the same cluster (codec-context band).
const CLUSTER_GAP: usize = 0x4000;
/// A cluster must hold at least this many anchors to be trusted as a codec band
/// (a lone stray anchor points at unrelated strings, e.g. `internal/cluster`).
const MIN_CLUSTER_ANCHORS: usize = 4;
/// How far to walk outward from a cluster center before giving up.
const CLUSTER_MAX_OUT: usize = 0x20000;
/// Collect at most this many key candidates per cluster.
///
/// Linux/Electron heaps can place a large certificate-string table between the
/// codec cluster center and the live key. Current QQ builds have been observed
/// with more than 150 distinct printable 16-byte windows before the key, so a
/// tiny "nearest few" cap truncates the search before verification can see it.
const CLUSTER_KEYS_PER: usize = 256;

fn is_non_space_printable(b: u8) -> bool {
    (0x21..0x7f).contains(&b)
}

fn is_alnum(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

/// A 16-byte window qualifies as a key candidate iff every byte is printable and
/// non-space, and they are not *all* alphanumeric (ordinary text is rejected).
fn key_ok(win: &[u8]) -> bool {
    win.len() == KEY_LEN
        && win.iter().all(|&b| is_non_space_printable(b))
        && !win.iter().all(|&b| is_alnum(b))
}

/// Count how many character classes occur: digit, uppercase, lowercase, symbol.
fn character_class_count(key: &[u8; KEY_LEN]) -> u8 {
    let mut classes = 0;
    classes += u8::from(key.iter().any(u8::is_ascii_digit));
    classes += u8::from(key.iter().any(u8::is_ascii_uppercase));
    classes += u8::from(key.iter().any(u8::is_ascii_lowercase));
    classes += u8::from(key.iter().any(|b| !b.is_ascii_alphanumeric()));
    classes
}

fn sort_candidates(candidates: &mut [Candidate]) {
    candidates.sort_by(|a, b| {
        character_class_count(&b.key)
            .cmp(&character_class_count(&a.key))
            .then_with(|| b.count.cmp(&a.count))
            .then_with(|| a.key.cmp(&b.key))
    });
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

/// How aggressively to search for the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Anchor-adjacent search only, plus the densest-cluster fallback. Fast.
    Normal,
    /// Additionally sweep every aligned window of every region — starting at
    /// the anchor band and wrapping around — verifying on the fly and stopping
    /// the instant a key validates.
    Strong,
}

/// Everything a scan produced. `verified` is the first candidate that matched
/// `settings.db` (what callers actually need); `candidates` is the ranked list
/// used for reporting when nothing verified.
pub struct ScanOutcome {
    pub candidates: Vec<Candidate>,
    pub verified: Option<Candidate>,
}

/// Read a whole region, honoring the per-region cap.
fn read_capped<A: ProcessAccess + Sync>(access: &A, region: &MemRegion) -> Vec<u8> {
    let size = region.size.min(MAX_REGION);
    // Unreadable regions are skipped, not fatal.
    access.read(region.base, size).unwrap_or_default()
}

/// If the batch carries candidates and one of them verifies, return the first
/// match (in batched order). `verify` returns the algo on success.
fn verify_batch(
    batch: &[[u8; KEY_LEN]],
    verify: &(impl Fn(&[u8; KEY_LEN]) -> bool + Sync),
) -> Option<[u8; KEY_LEN]> {
    batch.par_iter().find_map_any(|k| verify(k).then_some(*k))
}

/// Apply `verify` to a bare key. A named helper keeps the closure types readable
/// at call sites and gives tests one place to stub verification.
fn verify_key(verify: &(impl Fn(&[u8; KEY_LEN]) -> bool + Sync), key: &[u8; KEY_LEN]) -> bool {
    verify(key)
}

/// Scan the process's readable regions for raw_key candidates. Candidates with
/// more character classes rank first, then more frequently observed candidates.
///
/// `verify` is called on candidates; the moment one verifies the scan returns
/// it (both modes). `progress` (optional) drives a UI progress bar incremented by
/// bytes read. Strong mode additionally sweeps every aligned window of every
/// region (starting at the anchor band) until a verifying key turns up.
pub fn scan<A, F>(
    access: &A,
    mode: Mode,
    verify: F,
    progress: Option<&ProgressBar>,
) -> std::io::Result<ScanOutcome>
where
    A: ProcessAccess + Sync,
    F: Fn(&[u8; KEY_LEN]) -> bool + Sync,
{
    let regions = access.regions()?;
    let strong = mode == Mode::Strong;
    // Strong mode reads every region twice (cheap anchor pass, then the outward
    // sweep), so its progress bar spans two byte-lengths' worth of work.
    if let Some(bar) = progress {
        let bytes: u64 = regions.iter().map(|r| r.size.min(MAX_REGION) as u64).sum();
        bar.set_length(if strong { bytes * 2 } else { bytes });
    }

    // Phase 1: read each region once, collect anchor-adjacent and cluster-center
    // candidates (both cheap). Regions run in parallel; every read ticks progress.
    let per_region: Vec<Vec<[u8; KEY_LEN]>> = regions
        .par_iter()
        .map(|region| {
            let data = read_capped(access, region);
            if let Some(bar) = progress {
                bar.inc(data.len() as u64);
            }
            if data.is_empty() {
                return Vec::new();
            }
            // Quick reject: no anchor at all (memmem's SIMD scan returns empty).
            let anchors = find_anchors(&data);
            if anchors.is_empty() {
                return Vec::new();
            }
            let mut found = Vec::new();
            for &anchor in &anchors {
                if let Some(k) = nearest_key(&data, anchor) {
                    found.push(k);
                }
            }
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

    let mut candidates: Vec<Candidate> =
        counts.into_iter().map(|(key, count)| Candidate { key, count }).collect();
    sort_candidates(&mut candidates);

    // Verify the ranked pool. Normal mode stops here; Strong continues if none hit.
    let verified = candidates
        .par_iter()
        .find_map_first(|c| verify_key(&verify, &c.key).then(|| c.clone()));
    if verified.is_some() || !strong {
        return Ok(ScanOutcome { candidates, verified });
    }

    // Phase 2 (Strong): sweep every aligned window of every region, starting at
    // the anchor band. Verification happens on the fly inside each region, so we
    // stop the instant a key validates. The shared "seen" set — seeded with the
    // phase-1 pool — keeps rejected candidates from being re-tested.
    let seen: Mutex<HashSet<[u8; KEY_LEN]>> =
        Mutex::new(candidates.iter().map(|c| c.key).collect());
    let found = regions.par_iter().find_map_any(|region| {
        let data = read_capped(access, region);
        if let Some(bar) = progress {
            bar.inc(data.len() as u64);
        }
        if data.is_empty() {
            return None;
        }
        strong_region_data(&data, &seen, &verify)
    });

    if let Some(key) = found {
        let candidate = Candidate { key, count: 1 };
        candidates.push(candidate.clone());
        sort_candidates(&mut candidates);
        return Ok(ScanOutcome { candidates, verified: Some(candidate) });
    }
    Ok(ScanOutcome { candidates, verified: None })
}

/// The pure-data half of Strong mode: sweep every aligned 16-byte window in one
/// region, starting at the first anchor so nearby windows are tested first, and
/// verify on the fly. Returns the first key that validates. With no anchors the
/// sweep still covers the whole region from offset 0, so a key with no codec
/// marker beside it is still reachable.
fn strong_region_data(
    data: &[u8],
    seen: &Mutex<HashSet<[u8; KEY_LEN]>>,
    verify: &(impl Fn(&[u8; KEY_LEN]) -> bool + Sync),
) -> Option<[u8; KEY_LEN]> {
    let n = data.len();
    if n < KEY_LEN {
        return None;
    }
    // A linear sweep visits each offset once; `seen` still dedupes keys shared
    // with phase 1 across regions. We start at the first anchor (nearby windows
    // verified first) and wrap around so the whole region is still covered.
    let start = find_anchors(data).first().map(|&a| (a / ALIGN) * ALIGN).unwrap_or(0);

    let mut batch: Vec<[u8; KEY_LEN]> = Vec::with_capacity(STRONG_VERIFY_BATCH);
    let mut tested = 0usize;
    let first_end = n - KEY_LEN + 1;
    // Step each range separately so alignment never drifts across the wrap.
    let offsets = (start..first_end).step_by(ALIGN).chain((0..start).step_by(ALIGN));
    for off in offsets {
        let window = &data[off..off + KEY_LEN];
        if key_ok(window) {
            let mut k = [0u8; KEY_LEN];
            k.copy_from_slice(window);
            batch.push(k);
        }
        if batch.len() >= STRONG_VERIFY_BATCH {
            if let Some(found) = drain_and_verify(&mut batch, seen, verify) {
                return Some(found);
            }
            tested += STRONG_VERIFY_BATCH;
            if tested >= STRONG_MAX_CANDIDATES {
                return None;
            }
        }
    }
    drain_and_verify(&mut batch, seen, verify)
}

/// Deduplicate a batch against `seen`, verify the fresh keys in parallel, and
/// clear the batch. Returns the first key that verifies, if any.
fn drain_and_verify(
    batch: &mut Vec<[u8; KEY_LEN]>,
    seen: &Mutex<HashSet<[u8; KEY_LEN]>>,
    verify: &(impl Fn(&[u8; KEY_LEN]) -> bool + Sync),
) -> Option<[u8; KEY_LEN]> {
    if batch.is_empty() {
        return None;
    }
    let fresh: Vec<[u8; KEY_LEN]> = {
        let mut seen = seen.lock().unwrap();
        batch.drain(..).filter(|k| seen.insert(*k)).collect()
    };
    verify_batch(&fresh, verify)
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

    /// Normal-mode scan whose verifier rejects everything, so the returned
    /// candidate list is exactly what the anchor/cluster paths collected.
    fn scan_candidates(acc: &FakeAccess) -> Vec<Candidate> {
        scan(acc, Mode::Normal, |_| false, None).unwrap().candidates
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
        let cands = scan_candidates(&acc);
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
        let cands = scan_candidates(&acc);

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
    fn electron_layout_searches_past_many_printable_decoys() {
        let mut buf = vec![0x00u8; 0x50000];
        let cluster_start = 0x18000;
        let n_anchors = MIN_CLUSTER_ANCHORS + 12;
        for i in 0..n_anchors {
            put_anchor(&mut buf, cluster_start + i * 0x200);
        }

        let cluster_end = cluster_start + (n_anchors - 1) * 0x200;
        let center = ((cluster_start + cluster_end) / 2 / ALIGN) * ALIGN;

        // Reproduce a certificate/string-table-heavy Electron heap with enough
        // nearer key-like windows to exceed the previous cap by a wide margin.
        for i in 1..=151 {
            let off = center + i * 0x100;
            let decoy = format!("cert-table-{i:05}");
            assert_eq!(decoy.len(), KEY_LEN);
            buf[off..off + KEY_LEN].copy_from_slice(decoy.as_bytes());
        }

        let key = *b"realKEY)abcDEF!<";
        let key_off = center + 152 * 0x100;
        assert!(key_off.abs_diff(center) <= CLUSTER_MAX_OUT);
        buf[key_off..key_off + KEY_LEN].copy_from_slice(&key);

        let acc = FakeAccess { base: 0x10000, data: buf };
        let cands = scan_candidates(&acc);
        assert!(
            cands.iter().any(|c| c.key == key),
            "cluster search must continue past large printable string tables"
        );
    }

    #[test]
    fn strong_mode_sweeps_far_from_anchors() {
        // A key beyond every Normal-mode reach (RADIUS and CLUSTER_MAX_OUT), yet
        // still inside the region. Strong mode must sweep out and find it.
        let mut buf = vec![0x00u8; 0x100000];
        let anchor = 0x1000;
        put_anchor(&mut buf, anchor);
        let key = *b"strongKEY!@#$%^&";
        let key_pos: usize = 0x80000;
        assert!(key_pos.abs_diff(anchor) > CLUSTER_MAX_OUT);
        buf[key_pos..key_pos + KEY_LEN].copy_from_slice(&key);

        let acc = FakeAccess { base: 0x10000, data: buf };
        // Normal mode cannot reach it.
        let normal = scan_candidates(&acc);
        assert!(!normal.iter().any(|c| c.key == key));

        // Strong mode verifies candidates on the fly and returns the key.
        let outcome = scan(
            &acc,
            Mode::Strong,
            |k| *k == key,
            None,
        )
        .unwrap();
        assert_eq!(outcome.verified.map(|c| c.key), Some(key));
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

    #[test]
    fn key_candidates_reject_spaces() {
        assert!(key_ok(b"Abcdef1234567!@#"));
        assert!(!key_ok(b"Abcdef 123456!@#"));
    }

    #[test]
    fn candidate_order_prefers_more_character_classes() {
        let mut cands = vec![
            Candidate { key: *b"!!!!!!!!!!!!!!!?", count: 99 },
            Candidate { key: *b"ABCDEF1234567!@#", count: 10 },
            Candidate { key: *b"Abcdef1234567!@#", count: 1 },
            Candidate { key: *b"abcdef1234567!@#", count: 20 },
            Candidate { key: *b"abcdefghijklmno!", count: 50 },
        ];

        sort_candidates(&mut cands);

        let class_counts: Vec<u8> =
            cands.iter().map(|candidate| character_class_count(&candidate.key)).collect();
        assert_eq!(class_counts, vec![4, 3, 3, 2, 1]);
        assert_eq!(cands[1].count, 20, "frequency breaks equal-class ties");
    }
}
