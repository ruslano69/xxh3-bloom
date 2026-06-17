# Rust cross-check benchmark

A Rust port of the same filters, used to isolate **language** (Go vs Rust) from
**hash/algorithm** choice. It mirrors the Go harness in
[`cmd/e2e`](../../cmd/e2e/main.go): fill N 8-byte keys, then time true-positive
and true-negative queries and measure the actual false-positive rate.

Three modes (`--mode`):

| Mode | What it runs |
|---|---|
| `siphash` | the [`bloomfilter`](https://crates.io/crates/bloomfilter) crate (classic, SipHash-1-3) — external baseline |
| `classic` | our classic filter ported to Rust (XXH3-128, identical scheme to the Go `Filter`) |
| `blocked` | our cache-local blocked filter ported to Rust (XXH3-128, identical to the Go `BlockedFilter`) |
| `simd` | **AVX2 split-block** filter (Impala/Parquet style, 256-bit block, k=8) — a *different* layout, used to isolate what SIMD buys (x86-64 only) |
| `simd512` | AVX2 split-block, **512-bit block = one full cache line** (8 lanes × 64 bits, k=8) — trades a little speed for lower FP (x86-64 only) |

```bash
cargo run --release -- --mode blocked  --capacity 200000000 --fill 100
cargo run --release -- --mode classic  --capacity 200000000 --fill 100
cargo run --release -- --mode siphash  --capacity 200000000 --fill 100
cargo run --release -- --mode simd     --capacity 200000000 --fill 100   # AVX2
```

Flags: `--mode`, `--capacity`, `--fill` (%), `--fp`, `--queries`.

## Why this matters

The `classic` and `blocked` modes use the **exact same XXH3-128 values and bit
formulas** as the Go code (including the v0.7.0 enhanced double-hashing probe
scheme). This was verified empirically: the false-positive *counts* match Go
bit-for-bit (the classic tier produced an identical `100,381` over 10M negative
queries), proving `zeebo/xxh3` and `xxhash-rust` produce identical hashes and that
the port is faithful. Any remaining timing difference is therefore purely
language/runtime.

## Measured results (Intel i7-7700, 200M elements, 100% fill, FP target 1%)

Classic tier (same algorithm, m = 1.917e9 bits, k = 7):

| Impl | Hash | Fill ns/op | Query TP | Query TN | FP |
|---|---|---|---|---|---|
| Rust `bloomfilter` crate | SipHash-1-3 | 619 | 559 | 229 | 1.007 % |
| Go (ours) | XXH3 | 400 | 316 | 225 | 1.004 % |
| Rust (ours) | XXH3 | 297 | 264 | 152 | 1.004 % |

Blocked tier (our approach):

| Impl | Fill ns/op | Query TP | Query TN | FP |
|---|---|---|---|---|
| Go (ours) | 138 | 136 | 98 | 1.441 % |
| Rust (ours) | 86 | 125 | 90 | 1.441 % |

(These blocked numbers predate the v0.7.0 enhanced-double-hashing fix; throughput
is unchanged — the probe step costs the same — but the measured FP is now lower
and closer to target. The Go↔Rust timing comparison, the point of this table, is
unaffected.)

## SIMD experiment (AVX2, Intel i7-7700, 200M elements, 100% fill, same memory ≈ 0.24 GB)

The `simd` mode is **not** the scalar blocked filter vectorized — our 512-bit block
with k arbitrary bits would need a scatter to build the mask, which AVX2 lacks.
Instead it is the canonical SIMD Bloom layout (Impala / Apache Parquet **split-block**):
a 256-bit block = 8 lanes × 32 bits, one bit set per lane via 8 fixed salts, so the
whole membership test is branchless — `set` is one `OR`+store, `check` is a single
`_mm256_testc_si256`. Tradeoff: one-bit-per-word constrains placement, so FP is a bit
worse at equal memory (measured below).

Measured back-to-back in one run (so machine state is shared — see the methodology note):

| Mode | Fill ns/op | Query TP ns | Query TN ns | FP |
|---|---|---|---|---|
| SIMD split-block (AVX2, k=8) | **51** | **63** | **48** | 1.524 % |
| blocked (scalar XXH3, k=7) | 130 | 79 | 76 | 1.226 % |
| classic (scalar XXH3, k=7) | 291 | 272 | 153 | 1.004 % |

SIMD vs scalar blocked: **fill ≈ 2.5×, TP query ≈ 1.25×, TN query ≈ 1.6×.**

The shape of that win is the real lesson:

- **Fill speeds up hugely (2.5×); the lookup barely (1.25×).** Fill is throughput-bound
  — the CPU pipelines many outstanding stores, so collapsing 7 scalar ops into a few
  SIMD ops pays off. The TP lookup is **memory-latency-bound**: both variants pay one
  cache miss to pull the block, and once the core is stalled waiting on RAM, doing the
  test in 1 instruction instead of 7 is mostly hidden.
- **This re-confirms "memory rules", at a new level.** We removed ~85% of the per-lookup
  CPU work and got only ~25% faster lookups — direct evidence the wall on the query path
  is memory, not compute. (Matches the observation that CPU never exceeded ~30% during
  these runs.)
- **AVX2 only here.** i7-7700 (Kaby Lake) has AVX2/FMA but **no AVX-512**, so the block is
  256-bit (2× would need AVX-512 `testc`). On a 128-byte-cache-line CPU (Apple Silicon)
  the block-vs-line ratio changes again — see `bloom_platform_notes`.

### Two registers per block (`simd512`): does it cost speed?

A natural follow-up: make the block a **full 64-byte cache line** (two `__m256i`,
8 lanes × 64 bits, still k=8) so the blocking penalty drops and FP improves. Measured
back-to-back at 200M, same memory:

| Mode | Block | Fill ns/op | TP ns | TN ns | FP |
|---|---|---|---|---|---|
| `simd` | 256-bit (½ line) | **51** | **62** | 45 | 1.524 % |
| `simd512` | 512-bit (1 line) | 70 | 74 | 50 | 1.282 % |
| `blocked` (scalar) | 512-bit | 129 | 78 | 76 | 1.226 % |

- **Cost is moderate, not 2×:** fill +37%, query +12–19%. It stays sub-2× precisely
  because it is still **one cache miss** — both halves live in the same line.
- **FP improves** 1.52% → 1.28%, nearly matching scalar blocked — confirming "bigger
  block, same k → smaller blocking penalty."
- **Why query slows more than expected — an AVX2 ceiling, not a flaw of two blocks:**
  the 256-bit version builds its mask fully in-vector (`_mm256_mullo_epi32` over 8 lanes),
  but the 512-bit/64-bit-lane version **cannot** — AVX2 has no 64-bit lane multiply
  (`_mm256_mullo_epi64` is AVX-512). So `simd512` builds the 8 masks **scalar**, and that
  part is not hidden under memory latency. On AVX-512 this variant would be both faster
  and have an in-vector mask build.
- **Net: a clean tradeoff triangle.** `simd` = fastest, worst FP; `simd512` = scalar-blocked
  accuracy and lookup but ~1.8× faster fill; `blocked` = best FP among blocked, slowest fill.

Conclusions:

- **At an identical hash + algorithm, Rust is ~1.2–1.6× faster than Go** — real,
  but not order-of-magnitude. The gap is smallest on memory-bound query paths
  (blocked TP/TN ≈ 1.1×), confirming the project's thesis: once you're bound by
  memory latency, language is secondary.
- **The hash dominated the earlier "Go beats Rust" result.** Same Rust classic
  filter: SipHash-1-3 `619 ns` → XXH3 `297 ns`. SipHash is slower *by design*
  (hash-flooding DoS resistance), a tradeoff our XXH3 filters do not make.
- **Both project hypotheses held, each in its own regime:** cache locality wins at
  scale (blocked ≈ 4× over classic); hash choice wins when the alternative is a
  genuinely slow hash (XXH3 vs SipHash ≈ 1.8×). The only wrong assumption was
  expecting XXH3 to beat *MurmurHash3* — two fast hashes are indistinguishable
  once out of cache.
