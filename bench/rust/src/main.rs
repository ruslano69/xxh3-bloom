// End-to-end Bloom filter benchmark mirroring the Go harness in cmd/e2e.
// Same methodology: fill N 8-byte little-endian keys, then time true-positive
// and true-negative queries and measure the actual false-positive rate.
//
// Three modes (--mode):
//   siphash  -> bloomfilter 3.0.1 crate (classic, SipHash-1-3) — the baseline
//   classic  -> our classic filter ported to Rust (XXH3-128, same scheme as Go)
//   blocked  -> our cache-local blocked filter ported to Rust (XXH3-128)
//
// Modes `classic` and `blocked` use the EXACT same algorithm and hash as the Go
// implementation, so comparing them against the Go numbers isolates language
// (Go vs Rust) from hash/algorithm choice.

use bloomfilter::Bloom;
use std::time::Instant;
use xxhash_rust::xxh3::{xxh3_128, xxh3_128_with_seed};

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
}
impl BlockedXXH3 {
    fn new(n: usize, fp: f64) -> Self {
        let (m, k) = estimate(n, fp);
        let num_blocks = ((m as f64) / BLOCK_BITS as f64).ceil() as u64;
        Self::raw(num_blocks.max(1), k.max(1))
    }
    fn raw(num_blocks: u64, k: u32) -> Self {
        let words = num_blocks as usize * BLOCK_WORDS;
        let backing = vec![0u64; words + BLOCK_WORDS]; // 64B slack for alignment
        let addr = backing.as_ptr() as usize;
        let off = ((64 - (addr & 63)) & 63) / 8; // offset to next 64-byte boundary, in u64 units
        BlockedXXH3 { backing, off, num_blocks, k }
    }
    #[inline]
    fn block_off(&self, key: u64) -> (usize, u32, u32) {
        let h = xxh3_128(&key.to_le_bytes());
        let hi = (h >> 64) as u64;
        let lo = h as u64;
        let block = (hi % self.num_blocks) as usize;
        (self.off + block * BLOCK_WORDS, lo as u32, (lo >> 32) as u32)
    }
}
impl Filter for BlockedXXH3 {
    #[inline]
    fn set(&mut self, key: u64) {
        let (off, h1, h2) = self.block_off(key);
        for i in 0..self.k {
            let bit = h1.wrapping_add(i.wrapping_mul(h2)) & BLOCK_MASK;
            self.backing[off + (bit >> 6) as usize] |= 1u64 << (bit & 63);
        }
    }
    #[inline]
    fn check(&self, key: u64) -> bool {
        let (off, h1, h2) = self.block_off(key);
        for i in 0..self.k {
            let bit = h1.wrapping_add(i.wrapping_mul(h2)) & BLOCK_MASK;
            if self.backing[off + (bit >> 6) as usize] & (1u64 << (bit & 63)) == 0 {
                return false;
            }
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

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode: String = arg(&args, "--mode").unwrap_or_else(|| "blocked".to_string());
    let capacity: u64 = arg(&args, "--capacity").unwrap_or(200_000_000);
    let fill_pct: f64 = arg(&args, "--fill").unwrap_or(100.0);
    let fp_rate: f64 = arg(&args, "--fp").unwrap_or(0.01);
    let queries: u64 = arg(&args, "--queries").unwrap_or(10_000_000);
    let fill_n = (capacity as f64 * fill_pct / 100.0) as u64;

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
