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

```bash
cargo run --release -- --mode blocked  --capacity 200000000 --fill 100
cargo run --release -- --mode classic  --capacity 200000000 --fill 100
cargo run --release -- --mode siphash  --capacity 200000000 --fill 100
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
