// End-to-end Bloom filter benchmark mirroring the Go harness in cmd/e2e.
// Same methodology: fill N 8-byte little-endian keys, then time true-positive
// and true-negative queries and measure the actual false-positive rate.
//
// Modes (--mode):
//   siphash  -> bloomfilter 3.0.1 crate (classic, SipHash-1-3) — the baseline
//   classic  -> our classic filter ported to Rust (XXH3-128, same scheme as Go)
//   blocked  -> our cache-local blocked filter ported to Rust (XXH3-128)
//   simd     -> AVX2 split-block 256-bit (8×32, k=8, fully vectorized mask)
//   simd512  -> AVX2 split-block 512-bit (8×64, k=8, scalar mask — AVX2 lacks mullo_epi64)
//   avx512   -> AVX-512F+DQ split-block 512-bit (8×64, k=8, fully vectorized mask via mullo_epi64)
//
// Modes `classic` and `blocked` use the EXACT same algorithm and hash as the Go
// implementation, so comparing them against the Go numbers isolates language
// (Go vs Rust) from hash/algorithm choice.

use bloomfilter::Bloom;
use std::time::Instant;
use xxhash_rust::xxh3::{xxh3_128, xxh3_128_with_seed};

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

const BLOCK_BITS: u64 = 512;
const BLOCK_WORDS: usize = 8;
const BLOCK_MASK: u32 = 511;

fn estimate(n: usize, fp: f64) -> (u64, u32) {
    let nf = n as f64;
    let m = (-1.0 * nf * fp.ln() / std::f64::consts::LN_2.powi(2)).ceil();
    let k = (std::f64::consts::LN_2 * m / nf).ceil();
    (m as u64, k as u32)
}

trait Filter {
    fn set(&mut self, key: u64);
    fn check(&self, key: u64) -> bool;
    fn bits(&self) -> u64;
    fn hashes(&self) -> u32;
}

// ---- SipHash crate baseline ----
struct SipFilter(Bloom<[u8; 8]>);
impl Filter for SipFilter {
    #[inline]
    fn set(&mut self, key: u64) {
        self.0.set(&key.to_le_bytes());
    }
    #[inline]
    fn check(&self, key: u64) -> bool {
        self.0.check(&key.to_le_bytes())
    }
    fn bits(&self) -> u64 {
        self.0.len()
    }
    fn hashes(&self) -> u32 {
        self.0.number_of_hash_functions() as u32
    }
}

// ---- Our classic filter (XXH3-128, same scheme as Go filter.go) ----
struct ClassicXXH3 {
    b: Vec<u64>,
    m: u64,
    k: u32,
}
impl ClassicXXH3 {
    fn new(n: usize, fp: f64) -> Self {
        let (m, k) = estimate(n, fp);
        let m = m.max(1);
        ClassicXXH3 {
            b: vec![0u64; ((m + 63) / 64) as usize],
            m,
            k: k.max(1),
        }
    }
    #[inline]
    fn base_hashes(key: u64) -> [u64; 4] {
        let data = key.to_le_bytes();
        let a = xxh3_128(&data);
        let bb = xxh3_128_with_seed(&data, 1);
        [a as u64, (a >> 64) as u64, bb as u64, (bb >> 64) as u64]
    }
    #[inline]
    fn loc(h: &[u64; 4], i: u64, m: u64) -> u64 {
        // identical formula to bits-and-blooms / our Go filter
        (h[(i % 2) as usize].wrapping_add(i.wrapping_mul(h[(2 + (((i + (i % 2)) % 4) / 2)) as usize]))) % m
    }
}
impl Filter for ClassicXXH3 {
    #[inline]
    fn set(&mut self, key: u64) {
        let h = Self::base_hashes(key);
        for i in 0..self.k as u64 {
            let bit = Self::loc(&h, i, self.m);
            self.b[(bit >> 6) as usize] |= 1u64 << (bit & 63);
        }
    }
    #[inline]
    fn check(&self, key: u64) -> bool {
        let h = Self::base_hashes(key);
        for i in 0..self.k as u64 {
            let bit = Self::loc(&h, i, self.m);
            if self.b[(bit >> 6) as usize] & (1u64 << (bit & 63)) == 0 {
                return false;
            }
        }
        true
    }
    fn bits(&self) -> u64 {
        self.m
    }
    fn hashes(&self) -> u32 {
        self.k
    }
}

// ---- Our blocked filter (XXH3-128, same scheme as Go filter_blocked.go) ----
struct BlockedXXH3 {
    backing: Vec<u64>,
    off: usize,
    num_blocks: u64,
    k: u32,
    fastrange: bool, // true: (hi*N)>>64 (Lemire) instead of hi % N (a 64-bit DIV)
}
impl BlockedXXH3 {
    fn new(n: usize, fp: f64) -> Self {
        // fastrange is the default: it is strictly faster and we keep no on-disk
        // format, so there is nothing to stay compatible with. `blocked-mod` still
        // builds the modulo variant for A/B comparison.
        Self::with_range(n, fp, true)
    }
    fn with_range(n: usize, fp: f64, fastrange: bool) -> Self {
        let (m, k) = estimate(n, fp);
        let num_blocks = ((m as f64) / BLOCK_BITS as f64).ceil() as u64;
        Self::raw(num_blocks.max(1), k.max(1), fastrange)
    }
    fn raw(num_blocks: u64, k: u32, fastrange: bool) -> Self {
        let words = num_blocks as usize * BLOCK_WORDS;
        let backing = vec![0u64; words + BLOCK_WORDS]; // 64B slack for alignment
        let addr = backing.as_ptr() as usize;
        let off = ((64 - (addr & 63)) & 63) / 8; // offset to next 64-byte boundary, in u64 units
        BlockedXXH3 { backing, off, num_blocks, k, fastrange }
    }
    #[inline]
    fn block_off(&self, key: u64) -> (usize, u32, u32) {
        let h = xxh3_128(&key.to_le_bytes());
        let hi = (h >> 64) as u64;
        let lo = h as u64;
        // Map hi into [0, num_blocks): modulo is a true 64-bit DIV on the critical
        // path before the load; fastrange is a single widening multiply + shift.
        let block = if self.fastrange {
            ((hi as u128 * self.num_blocks as u128) >> 64) as usize
        } else {
            (hi % self.num_blocks) as usize
        };
        // odd stride for enhanced double hashing (matches the Go library)
        (self.off + block * BLOCK_WORDS, lo as u32, ((lo >> 32) as u32) | 1)
    }
}
impl Filter for BlockedXXH3 {
    #[inline]
    fn set(&mut self, key: u64) {
        let (off, mut a, mut b) = self.block_off(key);
        for i in 0..self.k {
            let bit = a & BLOCK_MASK;
            self.backing[off + (bit >> 6) as usize] |= 1u64 << (bit & 63);
            a = a.wrapping_add(b);
            b = b.wrapping_add(i); // enhanced double hashing: triangular term
        }
    }
    #[inline]
    fn check(&self, key: u64) -> bool {
        let (off, mut a, mut b) = self.block_off(key);
        for i in 0..self.k {
            let bit = a & BLOCK_MASK;
            if self.backing[off + (bit >> 6) as usize] & (1u64 << (bit & 63)) == 0 {
                return false;
            }
            a = a.wrapping_add(b);
            b = b.wrapping_add(i);
        }
        true
    }
    fn bits(&self) -> u64 {
        self.num_blocks * BLOCK_BITS
    }
    fn hashes(&self) -> u32 {
        self.k
    }
}

// ---- AVX2 split-block filter (Impala / Parquet style, register-blocked) ----
// This is NOT our scalar blocked filter vectorized — it is the canonical SIMD
// Bloom layout: each block is 256 bits = 8 lanes x 32 bits, and one bit is set
// per lane. The whole k=8 membership test collapses to ~5 SIMD ops, branchless:
//   set   -> block |= mask          (one OR + store)
//   check -> _mm256_testc(block, mask)   (one instruction)
// Tradeoff: one-bit-per-32-bit-word constrains placement, so FP is slightly
// worse than a true k=8 Bloom at equal memory — we measure the real FP below.
#[cfg(target_arch = "x86_64")]
const SALT: [u32; 8] = [
    0x47b6_137b, 0x4497_4d91, 0x8824_ad5b, 0xa2b7_289d,
    0x7054_95c7, 0x2df1_424c, 0x9efc_4947, 0x5c6b_fb31,
];

#[cfg(target_arch = "x86_64")]
struct SimdBlocked {
    backing: Vec<u32>, // num_blocks * 8 lanes, contiguous
    num_blocks: u64,
}

#[cfg(target_arch = "x86_64")]
impl SimdBlocked {
    fn new(n: usize, fp: f64) -> Self {
        if !is_x86_feature_detected!("avx2") {
            panic!("CPU lacks AVX2 — cannot run the simd mode here");
        }
        let (m, _k) = estimate(n, fp);
        // 256 bits per block; size to roughly the same total memory as scalar blocked.
        let num_blocks = ((m as f64) / 256.0).ceil() as u64;
        let num_blocks = num_blocks.max(1);
        SimdBlocked {
            backing: vec![0u32; num_blocks as usize * 8],
            num_blocks,
        }
    }

    // Build the 8-lane mask: one bit per 32-bit lane, index = (key32*SALT[lane]) >> 27.
    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn make_mask(key32: u32) -> __m256i {
        let salt = _mm256_setr_epi32(
            SALT[0] as i32, SALT[1] as i32, SALT[2] as i32, SALT[3] as i32,
            SALT[4] as i32, SALT[5] as i32, SALT[6] as i32, SALT[7] as i32,
        );
        let key_vec = _mm256_set1_epi32(key32 as i32);
        let prod = _mm256_mullo_epi32(key_vec, salt); // 8x key*salt
        let idx = _mm256_srli_epi32::<27>(prod); // top 5 bits -> 0..31
        let ones = _mm256_set1_epi32(1);
        _mm256_sllv_epi32(ones, idx) // 1 << idx per lane
    }

    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn set_avx2(&mut self, key: u64) {
        let h = xxh3_128(&key.to_le_bytes());
        let block = ((h >> 64) as u64 % self.num_blocks) as usize;
        let mask = Self::make_mask(h as u32);
        let p = self.backing.as_mut_ptr().add(block * 8) as *mut __m256i;
        let cur = _mm256_loadu_si256(p);
        _mm256_storeu_si256(p, _mm256_or_si256(cur, mask));
    }

    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn check_avx2(&self, key: u64) -> bool {
        let h = xxh3_128(&key.to_le_bytes());
        let block = ((h >> 64) as u64 % self.num_blocks) as usize;
        let mask = Self::make_mask(h as u32);
        let p = self.backing.as_ptr().add(block * 8) as *const __m256i;
        let cur = _mm256_loadu_si256(p);
        // testc(a,b) == 1  iff  all bits of b are set in a  (containment)
        _mm256_testc_si256(cur, mask) != 0
    }
}

#[cfg(target_arch = "x86_64")]
impl Filter for SimdBlocked {
    #[inline]
    fn set(&mut self, key: u64) {
        unsafe { self.set_avx2(key) }
    }
    #[inline]
    fn check(&self, key: u64) -> bool {
        unsafe { self.check_avx2(key) }
    }
    fn bits(&self) -> u64 {
        self.num_blocks * 256
    }
    fn hashes(&self) -> u32 {
        8 // one bit per lane
    }
}

// Two-phase batch (hash+prefetch a window, then apply) for the simd tier. The
// vectorized mask (saves compute) and the prefetch (hides the cache miss)
// compose: this is the "promising path" the Go side already showed beats the
// scalar-blocked batch. We store only (offset, key32) and rebuild the mask in
// phase 2 — the rebuild is cheap and fully overlapped with the arriving line.
#[cfg(target_arch = "x86_64")]
impl SimdBlocked {
    #[target_feature(enable = "avx2")]
    unsafe fn set_batch_avx2(&mut self, keys: &[u64], chunk: usize) {
        let chunk = chunk.max(1);
        let mut probes: Vec<(usize, u32)> = vec![(0, 0); chunk];
        let mut base = 0;
        while base < keys.len() {
            let end = (base + chunk).min(keys.len());
            let c = end - base;
            for j in 0..c {
                let h = xxh3_128(&keys[base + j].to_le_bytes());
                let off = ((h >> 64) as u64 % self.num_blocks) as usize * 8;
                prefetch(self.backing.as_ptr().add(off) as *const u64);
                probes[j] = (off, h as u32);
            }
            for j in 0..c {
                let (off, key32) = probes[j];
                let mask = Self::make_mask(key32);
                let p = self.backing.as_mut_ptr().add(off) as *mut __m256i;
                let cur = _mm256_loadu_si256(p);
                _mm256_storeu_si256(p, _mm256_or_si256(cur, mask));
            }
            base = end;
        }
    }

    #[target_feature(enable = "avx2")]
    unsafe fn check_batch_avx2(&self, keys: &[u64], out: &mut [bool], chunk: usize) {
        let chunk = chunk.max(1);
        let mut probes: Vec<(usize, u32)> = vec![(0, 0); chunk];
        let mut base = 0;
        while base < keys.len() {
            let end = (base + chunk).min(keys.len());
            let c = end - base;
            for j in 0..c {
                let h = xxh3_128(&keys[base + j].to_le_bytes());
                let off = ((h >> 64) as u64 % self.num_blocks) as usize * 8;
                prefetch(self.backing.as_ptr().add(off) as *const u64);
                probes[j] = (off, h as u32);
            }
            for j in 0..c {
                let (off, key32) = probes[j];
                let mask = Self::make_mask(key32);
                let p = self.backing.as_ptr().add(off) as *const __m256i;
                let cur = _mm256_loadu_si256(p);
                out[base + j] = _mm256_testc_si256(cur, mask) != 0;
            }
            base = end;
        }
    }
}

// ---- AVX2 split-block, 512-bit variant (8 lanes x 64 bits, k=8) ----
// Same idea as SimdBlocked but the block is a FULL 64-byte cache line: two
// __m256i halves, each 4x 64-bit lanes, one bit set per 64-bit lane. Keeping
// k=8 (not 16) while doubling the block lowers the blocking penalty, so FP
// improves toward the scalar 512-bit blocked filter — at still ONE cache miss.
// Requires 64-byte alignment, else a line-sized block straddles two lines.
#[cfg(target_arch = "x86_64")]
const SALT64: [u64; 8] = [
    0x9E37_79B9_7F4A_7C15, 0xBF58_476D_1CE4_E5B9,
    0x94D0_49BB_1331_11EB, 0x2545_F491_4F6C_DD1D,
    0xFF51_AFD7_ED55_8CCD, 0xC4CE_B9FE_1A85_EC53,
    0xD6E8_FEB8_6659_FD93, 0xA076_1D64_78BD_642F,
];

#[cfg(target_arch = "x86_64")]
struct SimdBlocked512 {
    backing: Vec<u64>, // num_blocks*8 lanes + slack, 64B-aligned via `off`
    off: usize,        // u64 offset to the first 64-byte boundary
    num_blocks: u64,
}

#[cfg(target_arch = "x86_64")]
impl SimdBlocked512 {
    fn new(n: usize, fp: f64) -> Self {
        if !is_x86_feature_detected!("avx2") {
            panic!("CPU lacks AVX2 — cannot run the simd512 mode here");
        }
        let (m, _k) = estimate(n, fp);
        let num_blocks = ((m as f64) / 512.0).ceil() as u64;
        let num_blocks = num_blocks.max(1);
        let words = num_blocks as usize * 8;
        let backing = vec![0u64; words + 8]; // 64B slack for alignment
        let addr = backing.as_ptr() as usize;
        let off = ((64 - (addr & 63)) & 63) / 8; // u64 units to next 64B boundary
        SimdBlocked512 { backing, off, num_blocks }
    }

    // 8 lane masks, one bit per 64-bit lane: idx = (klo*SALT64[i]) >> 58  (0..63).
    #[inline]
    fn make_mask(klo: u64) -> [u64; 8] {
        let mut m = [0u64; 8];
        for i in 0..8 {
            let idx = (klo.wrapping_mul(SALT64[i]) >> 58) as u32;
            m[i] = 1u64 << idx;
        }
        m
    }

    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn set_avx2(&mut self, key: u64) {
        let h = xxh3_128(&key.to_le_bytes());
        let block = ((h >> 64) as u64 % self.num_blocks) as usize;
        let m = Self::make_mask(h as u64);
        let base = self.backing.as_mut_ptr().add(self.off + block * 8);
        let plo = base as *mut __m256i;
        let phi = base.add(4) as *mut __m256i;
        let mlo = _mm256_setr_epi64x(m[0] as i64, m[1] as i64, m[2] as i64, m[3] as i64);
        let mhi = _mm256_setr_epi64x(m[4] as i64, m[5] as i64, m[6] as i64, m[7] as i64);
        _mm256_storeu_si256(plo, _mm256_or_si256(_mm256_loadu_si256(plo), mlo));
        _mm256_storeu_si256(phi, _mm256_or_si256(_mm256_loadu_si256(phi), mhi));
    }

    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn check_avx2(&self, key: u64) -> bool {
        let h = xxh3_128(&key.to_le_bytes());
        let block = ((h >> 64) as u64 % self.num_blocks) as usize;
        let m = Self::make_mask(h as u64);
        let base = self.backing.as_ptr().add(self.off + block * 8);
        let plo = base as *const __m256i;
        let phi = base.add(4) as *const __m256i;
        let mlo = _mm256_setr_epi64x(m[0] as i64, m[1] as i64, m[2] as i64, m[3] as i64);
        let mhi = _mm256_setr_epi64x(m[4] as i64, m[5] as i64, m[6] as i64, m[7] as i64);
        _mm256_testc_si256(_mm256_loadu_si256(plo), mlo) != 0
            && _mm256_testc_si256(_mm256_loadu_si256(phi), mhi) != 0
    }
}

#[cfg(target_arch = "x86_64")]
impl Filter for SimdBlocked512 {
    #[inline]
    fn set(&mut self, key: u64) {
        unsafe { self.set_avx2(key) }
    }
    #[inline]
    fn check(&self, key: u64) -> bool {
        unsafe { self.check_avx2(key) }
    }
    fn bits(&self) -> u64 {
        self.num_blocks * 512
    }
    fn hashes(&self) -> u32 {
        8
    }
}

// ---- AVX-512 split-block filter (AVX-512F + AVX-512DQ, 512-bit = 1 cache line, k=8) ----
// Identical block layout to SimdBlocked512, but the mask is built FULLY IN-VECTOR:
//   _mm512_mullo_epi64  (AVX-512DQ) — 64-bit lane multiply, missing in AVX2
//   _mm512_sllv_epi64  (AVX-512F)  — variable shift per lane
// One __m512i register holds the whole block, so set/check collapse to:
//   set   -> block = _mm512_or_si512(block, mask)   (1 load, 1 OR, 1 store)
//   check -> t = andnot(block, mask); contained iff test_epi64_mask(t,t) == 0
//
// NOTE: _mm512_mullo_epi64 requires AVX-512DQ (Zen 4 / Ice Lake+).
//       The binary is safe on older CPUs: the runtime check panics before any
//       AVX-512 instruction executes. Validate FP on first Zen 4 run.
#[cfg(target_arch = "x86_64")]
struct SimdBlocked512Avx512 {
    backing: Vec<u64>, // num_blocks*8 lanes + 8 slack, 64B-aligned via `off`
    off: usize,        // u64 offset to the first 64-byte boundary
    num_blocks: u64,
}

#[cfg(target_arch = "x86_64")]
impl SimdBlocked512Avx512 {
    fn new(n: usize, fp: f64) -> Self {
        if !is_x86_feature_detected!("avx512f") || !is_x86_feature_detected!("avx512dq") {
            panic!("CPU lacks AVX-512F+DQ — cannot run avx512 mode here");
        }
        let (m, _k) = estimate(n, fp);
        let num_blocks = ((m as f64) / 512.0).ceil() as u64;
        let num_blocks = num_blocks.max(1);
        let words = num_blocks as usize * 8;
        let backing = vec![0u64; words + 8]; // 64B slack for alignment
        let addr = backing.as_ptr() as usize;
        let off = ((64 - (addr & 63)) & 63) / 8;
        SimdBlocked512Avx512 { backing, off, num_blocks }
    }

    // Build 8-lane mask fully in-vector: idx = (klo * SALT64[lane]) >> 58 → 0..63
    // Requires AVX-512DQ for _mm512_mullo_epi64.
    #[inline]
    #[target_feature(enable = "avx512f,avx512dq")]
    unsafe fn make_mask(klo: u64) -> __m512i {
        let key_vec = _mm512_set1_epi64(klo as i64);
        // _mm512_set_epi64 args: e7..e0, so pass SALT64[7..0] to put SALT64[i] in lane i.
        let salt_vec = _mm512_set_epi64(
            SALT64[7] as i64, SALT64[6] as i64, SALT64[5] as i64, SALT64[4] as i64,
            SALT64[3] as i64, SALT64[2] as i64, SALT64[1] as i64, SALT64[0] as i64,
        );
        let prod = _mm512_mullo_epi64(key_vec, salt_vec); // klo * salt per lane
        let idx  = _mm512_srli_epi64::<58>(prod);         // top 6 bits → 0..63
        _mm512_sllv_epi64(_mm512_set1_epi64(1), idx)      // 1 << idx per lane
    }

    #[inline]
    #[target_feature(enable = "avx512f,avx512dq")]
    unsafe fn set_avx512(&mut self, key: u64) {
        let h = xxh3_128(&key.to_le_bytes());
        let hi = (h >> 64) as u64;
        let lo = h as u64;
        let block = ((hi as u128 * self.num_blocks as u128) >> 64) as usize; // fastrange
        let mask = Self::make_mask(lo);
        let p = self.backing.as_mut_ptr().add(self.off + block * 8) as *mut __m512i;
        let cur = _mm512_loadu_si512(p as *const __m512i);
        _mm512_storeu_si512(p, _mm512_or_si512(cur, mask));
    }

    #[inline]
    #[target_feature(enable = "avx512f,avx512dq")]
    unsafe fn check_avx512(&self, key: u64) -> bool {
        let h = xxh3_128(&key.to_le_bytes());
        let hi = (h >> 64) as u64;
        let lo = h as u64;
        let block = ((hi as u128 * self.num_blocks as u128) >> 64) as usize;
        let mask = Self::make_mask(lo);
        let p = self.backing.as_ptr().add(self.off + block * 8) as *const __m512i;
        let cur = _mm512_loadu_si512(p);
        // t = bits in mask that are NOT in cur; contained iff t is all-zero.
        let t = _mm512_andnot_si512(cur, mask);
        _mm512_test_epi64_mask(t, t) == 0
    }
}

#[cfg(target_arch = "x86_64")]
impl Filter for SimdBlocked512Avx512 {
    #[inline]
    fn set(&mut self, key: u64) {
        unsafe { self.set_avx512(key) }
    }
    #[inline]
    fn check(&self, key: u64) -> bool {
        unsafe { self.check_avx512(key) }
    }
    fn bits(&self) -> u64 {
        self.num_blocks * 512
    }
    fn hashes(&self) -> u32 {
        8
    }
}

// ---- Batch query with software prefetch (memory-level parallelism) ----
#[inline(always)]
fn prefetch(p: *const u64) {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        _mm_prefetch::<{ _MM_HINT_T0 }>(p as *const i8);
    }
    #[cfg(not(target_arch = "x86_64"))]
    let _ = p;
}

impl BlockedXXH3 {
    // Chunked two-phase batch test: hash a chunk of keys and prefetch all their
    // cache lines, then run the k-probe checks once the lines are arriving. This
    // keeps many misses in flight (memory-level parallelism) instead of one per
    // dependent lookup. `chunk` is the prefetch window we sweep.
    fn check_batch(&self, keys: &[u64], out: &mut [bool], chunk: usize) {
        let chunk = chunk.max(1);
        let mut probes: Vec<(usize, u32, u32)> = vec![(0, 0, 0); chunk];
        let mut base = 0;
        while base < keys.len() {
            let end = (base + chunk).min(keys.len());
            let c = end - base;
            // phase 1: hash + prefetch each key's block line
            for j in 0..c {
                let p = self.block_off(keys[base + j]);
                prefetch(unsafe { self.backing.as_ptr().add(p.0) });
                probes[j] = p;
            }
            // phase 2: probe (lines now in or arriving to cache)
            for j in 0..c {
                let (off, mut a, mut b) = probes[j];
                let mut hit = true;
                for i in 0..self.k {
                    let bit = a & BLOCK_MASK;
                    if self.backing[off + (bit >> 6) as usize] & (1u64 << (bit & 63)) == 0 {
                        hit = false;
                        break;
                    }
                    a = a.wrapping_add(b);
                    b = b.wrapping_add(i);
                }
                out[base + j] = hit;
            }
            base = end;
        }
    }
}

fn run_batch(capacity: u64, fill_pct: f64, fp: f64, queries: u64) {
    let fill_n = (capacity as f64 * fill_pct / 100.0) as u64;
    let mut f = BlockedXXH3::with_range(capacity as usize, fp, true); // fastrange base
    println!("=== Rust BATCH (blocked, fastrange) — MLP / prefetch sweep ===");
    println!("Capacity : {} elements   Fill: {}", commas(capacity), commas(fill_n));
    println!("Bits (m) : {}  ({:.2} GB)   k = {}\n",
        commas(f.bits()), f.bits() as f64 / 8.0 / 1e9, f.hashes());

    let start = Instant::now();
    for i in 0..fill_n {
        f.set(i);
    }
    println!("[Fill] {:.0} ns/op\n", start.elapsed().as_nanos() as f64 / fill_n as f64);

    // true positives: every key present, so each probe must load its block
    let qkeys: Vec<u64> = (0..queries).map(|i| i % fill_n).collect();
    let mut out = vec![false; queries as usize];

    println!("[TP batch query — ns/op by prefetch window]  (chunk=1 ≈ no MLP baseline)");
    for &chunk in &[1usize, 2, 4, 8, 16, 32, 64, 128, 256] {
        let start = Instant::now();
        f.check_batch(&qkeys, &mut out, chunk);
        let d = start.elapsed();
        let hits = out.iter().filter(|&&b| b).count();
        let ns = d.as_nanos() as f64 / queries as f64;
        println!("  chunk={:4}  {:6.1} ns/op  {:6.1} M/s  hits={}",
            chunk, ns, 1e3 / ns, commas(hits as u64));
        assert_eq!(hits as u64, queries, "false negatives at chunk {}", chunk);
    }
}

// run_batch_simd is the SIMD counterpart of run_batch: it sweeps the prefetch
// window for the 256-bit split-block filter on both the fill and query paths,
// so we can see how the vectorized mask + MLP combine against the scalar batch.
#[cfg(target_arch = "x86_64")]
fn run_batch_simd(capacity: u64, fill_pct: f64, fp: f64, queries: u64) {
    let fill_n = (capacity as f64 * fill_pct / 100.0) as u64;
    let f0 = SimdBlocked::new(capacity as usize, fp);
    println!("=== Rust BATCH (simd 256-bit, AVX2) — MLP / prefetch sweep ===");
    println!("Capacity : {} elements   Fill: {}", commas(capacity), commas(fill_n));
    println!("Bits (m) : {}  ({:.2} GB)   k = {}\n",
        commas(f0.bits()), f0.bits() as f64 / 8.0 / 1e9, f0.hashes());

    let fkeys: Vec<u64> = (0..fill_n).collect();
    println!("[Fill batch — ns/op by prefetch window]  (chunk=1 ≈ no MLP baseline)");
    for &chunk in &[1usize, 8, 16, 32, 64] {
        let mut ff = SimdBlocked::new(capacity as usize, fp);
        let start = Instant::now();
        unsafe { ff.set_batch_avx2(&fkeys, chunk) };
        let ns = start.elapsed().as_nanos() as f64 / fill_n as f64;
        println!("  chunk={:4}  {:6.1} ns/op", chunk, ns);
    }

    let mut f = SimdBlocked::new(capacity as usize, fp);
    unsafe { f.set_batch_avx2(&fkeys, 16) };
    let qkeys: Vec<u64> = (0..queries).map(|i| i % fill_n).collect();
    let mut out = vec![false; queries as usize];
    println!("\n[TP batch query — ns/op by prefetch window]  (chunk=1 ≈ no MLP baseline)");
    for &chunk in &[1usize, 2, 4, 8, 16, 32, 64, 128] {
        let start = Instant::now();
        unsafe { f.check_batch_avx2(&qkeys, &mut out, chunk) };
        let d = start.elapsed();
        let hits = out.iter().filter(|&&b| b).count();
        let ns = d.as_nanos() as f64 / queries as f64;
        println!("  chunk={:4}  {:6.1} ns/op  hits={}", chunk, ns, commas(hits as u64));
        assert_eq!(hits as u64, queries, "false negatives at chunk {}", chunk);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode: String = arg(&args, "--mode").unwrap_or_else(|| "blocked".to_string());
    let capacity: u64 = arg(&args, "--capacity").unwrap_or(200_000_000);
    let fill_pct: f64 = arg(&args, "--fill").unwrap_or(100.0);
    let fp_rate: f64 = arg(&args, "--fp").unwrap_or(0.01);
    let queries: u64 = arg(&args, "--queries").unwrap_or(10_000_000);
    let fill_n = (capacity as f64 * fill_pct / 100.0) as u64;

    if args.iter().any(|a| a == "--batch") {
        #[cfg(target_arch = "x86_64")]
        if mode == "simd" {
            run_batch_simd(capacity, fill_pct, fp_rate, queries);
            return;
        }
        run_batch(capacity, fill_pct, fp_rate, queries);
        return;
    }

    let (label, filter): (&str, Box<dyn Filter>) = match mode.as_str() {
        "siphash" => (
            "Rust siphash crate (classic)",
            Box::new(SipFilter(
                Bloom::new_for_fp_rate(capacity as usize, fp_rate).expect("alloc"),
            )),
        ),
        "classic" => (
            "Rust classic (our XXH3 scheme)",
            Box::new(ClassicXXH3::new(capacity as usize, fp_rate)),
        ),
        "blocked-mod" => (
            "Rust blocked (XXH3, modulo block index — baseline)",
            Box::new(BlockedXXH3::with_range(capacity as usize, fp_rate, false)),
        ),
        #[cfg(target_arch = "x86_64")]
        "simd" => (
            "Rust SIMD split-block (AVX2, 256-bit, k=8)",
            Box::new(SimdBlocked::new(capacity as usize, fp_rate)),
        ),
        #[cfg(target_arch = "x86_64")]
        "simd512" => (
            "Rust SIMD split-block (AVX2, 512-bit = 1 cache line, k=8)",
            Box::new(SimdBlocked512::new(capacity as usize, fp_rate)),
        ),
        #[cfg(target_arch = "x86_64")]
        "avx512" => (
            "Rust SIMD split-block (AVX-512F+DQ, 512-bit = 1 cache line, k=8, vectorized mask)",
            Box::new(SimdBlocked512Avx512::new(capacity as usize, fp_rate)),
        ),
        _ => (
            "Rust blocked (our XXH3 scheme)",
            Box::new(BlockedXXH3::new(capacity as usize, fp_rate)),
        ),
    };

    println!("=== Rust E2E :: {} ===", label);
    println!("Capacity : {} elements", commas(capacity));
    println!("Fill     : {:.1}% = {} elements", fill_pct, commas(fill_n));
    println!("Bits (m) : {}  ({:.2} GB)   k = {}\n",
        commas(filter.bits()), filter.bits() as f64 / 8.0 / 1e9, filter.hashes());

    run(filter, fill_n, capacity, fp_rate, queries);
}

fn run(mut f: Box<dyn Filter>, fill_n: u64, capacity: u64, fp_rate: f64, queries: u64) {
    // Fill
    println!("[Fill phase]");
    let start = Instant::now();
    for i in 0..fill_n {
        f.set(i);
    }
    let d = start.elapsed();
    let ns = d.as_nanos() as f64 / fill_n as f64;
    println!("  Done: {} ops in {:.0}s = {:.0} ns/op = {:.2}M ops/sec\n",
        commas(fill_n), d.as_secs_f64(), ns, 1e9 / ns / 1e6);

    // True positives
    println!("[Query phase \u{2014} true positives]");
    let start = Instant::now();
    let mut hits = 0u64;
    for i in 0..queries {
        if f.check(i % fill_n) {
            hits += 1;
        }
    }
    let d = start.elapsed();
    println!("  {} queries in {:.0}s = {:.0} ns/op = {:.2}M ops/sec  (hits={})",
        commas(queries), d.as_secs_f64(),
        d.as_nanos() as f64 / queries as f64,
        queries as f64 / d.as_secs_f64() / 1e6, commas(hits));

    // True negatives / FP
    println!("\n[Query phase \u{2014} true negatives]");
    let start = Instant::now();
    let mut fp = 0u64;
    for i in 0..queries {
        if f.check(capacity + i + 1) {
            fp += 1;
        }
    }
    let d = start.elapsed();
    println!("  {} queries in {:.0}s = {:.0} ns/op = {:.2}M ops/sec",
        commas(queries), d.as_secs_f64(),
        d.as_nanos() as f64 / queries as f64,
        queries as f64 / d.as_secs_f64() / 1e6);
    println!("  False positives: {} / {} = {:.4}% (target {:.2}%)",
        commas(fp), commas(queries),
        fp as f64 / queries as f64 * 100.0, fp_rate * 100.0);
}

fn arg<T: std::str::FromStr>(args: &[String], name: &str) -> Option<T> {
    let pos = args.iter().position(|a| a == name)?;
    args.get(pos + 1)?.parse().ok()
}

fn commas(n: u64) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in bytes.iter().enumerate() {
        if i > 0 && (bytes.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(*c as char);
    }
    out
}
