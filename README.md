# bloom — cache-local Bloom filter

A Go Bloom filter focused on **lookup speed through memory locality**, not through
the hash function. API-compatible with
[`bits-and-blooms/bloom`](https://github.com/bits-and-blooms/bloom).

At its core this is a **low-level optimization of the membership-lookup algorithm**:
the same Bloom filter, but with its bits laid out for the CPU cache.

> **The honest one-liner:** the lookup speedup (~2.9×) comes from
> **single-cache-line probing**, not from the choice of hash. XXH3 is an
> *implementation detail*, not the source of speed.

## What's inside

| Tier | File | Idea |
|---|---|---|
| `Filter` | [`filter.go`](filter.go) | Classic filter, XXH3 drop-in instead of MurmurHash3 |
| `BlockedFilter` | [`filter_blocked.go`](filter_blocked.go) | All `k` bits of a key live in one 64-byte cache line → 1 cache miss instead of `k` |
| `NewBlockedTuned` | [`filter_blocked.go`](filter_blocked.go) | Same, but the block count is numerically sized to hit the target FP (spend ~10% more RAM, get the accuracy back) |

## Where the speed comes from (and where it doesn't)

This started as the hypothesis "swap MurmurHash3 for XXH3 and it'll be faster."
We **tested it and disproved it**: on large filters (out of the L3 cache) the
bottleneck is not computing the hash, it's the random memory access. The hash
function is invisible there.

Measured on Intel i7-7700, 200M elements, 100% fill, FP target 1%:

| Tier | Fill ns/op | Query ns/op | FP rate | Memory | Cache misses / op |
|---|---|---|---|---|---|
| Murmur3 (original) | ~400 | 316 | 1.00 % | 0.24 GB | 7 |
| **XXH3** (drop-in) | 400 | 316 | 1.00 % | 0.24 GB | 7 |
| **Blocked-XXH3** | **138** | **136** | 1.44 % ⚠️ | 0.24 GB | **1** |
| **Blocked-Tuned** | **141** | **138** | **1.01 %** ✅ | 0.26 GB | **1** |

Takeaways:
- **XXH3 vs Murmur3 — a tie.** Once the filter doesn't fit in cache, hash choice
  is irrelevant.
- **Blocked gives ~2.9×** by collapsing 7 cache misses into 1.
- **Plain Blocked trades accuracy** (1.44 % instead of 1.00 %) because of uneven
  block load (Poisson distribution of keys across blocks).
- **Blocked-Tuned** brings accuracy back to target at the cost of **+10 % memory** —
  the best balance when you have spare RAM.

On *small* filters (those that fit in L3, < ~700K elements at 1% FP) XXH3 really is
a bit faster than Murmur3 (~10–15 % on short keys), because there computation
dominates rather than memory. That shows up in the micro-benchmarks.

## The "convenient property" of XXH3 we rely on

Not speed. We rely on the fact that **a single alloc-free `xxh3.Hash128` call hands
back exactly the shape of data a blocked filter needs**:

```go
h := xxh3.Hash128(data)        // one call, zero allocations, 128 bits
blockIdx := h.Hi % numBlocks   // high 64 bits → pick the cache line
h1 := uint32(h.Lo)             // low 64 bits, lower half
h2 := uint32(h.Lo >> 32)       //              upper half
// k positions inside the block — Kirsch-Mitzenmacher double hashing:
//   bit_i = (h1 + i*h2) mod 512
```

So from one hash we get both the **block index** and the **seed for in-block
double-hashing** for free — no second pass over the data, no heap. The classic
`bits-and-blooms` runs Murmur3-128 twice for this (see `sum256`); one `Hash128` is
enough for us. That's a simplification, not a faster hash.

## Usage

```go
import bloom "github.com/ruslano69/xxh3-bloom"

// Classic (minimum memory, exact FP)
f := bloom.NewWithEstimates(1_000_000, 0.01)
f.Add([]byte("key"))
ok := f.Test([]byte("key"))

// Cache-local (need throughput, accuracy not critical)
b := bloom.NewBlocked(1_000_000, 0.01)

// Cache-local + exact FP (you have spare RAM)
t := bloom.NewBlockedTuned(1_000_000, 0.01)

// Configured with options (seed, hash)
seed := bloom.RandomSeed()                 // crypto-random, keep it secret
s := bloom.NewBlockedTuned(1_000_000, 0.01,
    bloom.WithSeed(seed),                  // key the hash (see Security below)
    bloom.WithHash(bloom.Murmur3),         // pick the hash function
)
```

Every constructor takes variadic `Option`s — `WithSeed(seed)` and
`WithHash(kind)` — and existing call sites without options keep working
unchanged. (The older `*WithSeed` constructors remain as deprecated shorthands.)

### Hash function

The default hash is `XXH3`. `WithHash(bloom.Murmur3)` switches to MurmurHash3-128,
and you can register your own with `RegisterHash(kind, hasher)` (kind ≥ 128). The
chosen hash is recorded in the serialized form, so a filter always reloads with
the hash it was built with.

⚠️ **Selecting `Murmur3` matches the hash used by `bits-and-blooms/bloom`, but
that alone does not make the filters bit-compatible** — true interop also requires
the same location formula, bit layout, and m/k rounding. Treat `WithHash` as
"choose the hashing primitive," not "drop-in interop with library X."

Picking a tier:

```
Memory-constrained, accuracy critical   → Filter (classic)
Have RAM, need throughput               → NewBlockedTuned
Accuracy not critical, want raw speed   → NewBlocked
```

### Serialization (blocked tiers only)

```go
// to disk
fd, _ := os.Create("filter.bbf")
w := bufio.NewWriter(fd)
t.WriteTo(w)
w.Flush(); fd.Close()

// from disk
var loaded bloom.BlockedFilter
fd2, _ := os.Open("filter.bbf")
loaded.ReadFrom(bufio.NewReader(fd2))
```

The bit array is dumped raw via `unsafe` (no reflection — a GB-scale filter would
take minutes through `binary.Write`). The format is self-describing: it records
the seed, hash kind, and the payload's byte order, so `WriteTo` always writes at
host speed and `ReadFrom` byte-swaps only on the rare cross-endian load — **files
are portable**. `WriteTo` bumps the version only when a field matters: an XXH3
filter is written as v3 (still readable by v0.3.0), a non-XXH3 filter as v4.

`ReadFrom` reads every historical version (v1–v4). To upgrade old files in bulk:

```
go run ./cmd/convert old.bbf new.bbf      # any version -> current
```

| Format | Header | Stores | Portable |
|---|---|---|---|
| v1 (`v0.1.0`) | 24 B | numBlocks, k | no (LE only) |
| v2 (`v0.2.0`) | 32 B | + seed | no (LE only) |
| v3 (`v0.3.0`) | 40 B | + endianness tag | yes |
| v4 (`v0.4.0`) | 40 B | + hash kind | yes |

## Security: hashing seed & threat model

XXH3, like MurmurHash3, is a **fast, non-cryptographic** hash with a fixed,
publicly known mapping. That's perfect for trusted data but has one consequence
worth understanding.

**Bloom filters are immune to classic hash-flooding** (the O(n²) hash-table
blow-up): every op is a fixed `O(k)` regardless of input, so you cannot make the
CPU collide its way to a stall. But there is a related attack — **filter
poisoning**: an attacker who knows your fixed hash can craft inputs that
maximize false positives (making the filter pass everything and stop protecting
the backend), or, for a blocked filter, saturate one specific cache line.

The mitigation is to turn XXH3 into a **keyed** hash with a secret per-process
seed (`RandomSeed()` + a `*WithSeed` constructor). Without the seed an attacker
can no longer precompute colliding inputs offline — which removes the vast
majority of the incentive to attack.

```
Keys are YOUR data (file paths, internal IDs you generate)   → unseeded is fine
Keys come from untrusted users who benefit from poisoning    → use *WithSeed
```

⚠️ **Caveat — not a MAC.** XXH3 with a seed is *not* a proven cryptographic
primitive the way SipHash (used by the `bloomfilter` crate, and by Rust/Python
hash maps) or HMAC is. Seeding defeats offline precomputation, which covers the
practical threat, but against a determined adversary who can mount adaptive
online attacks, prefer a keyed cryptographic hash. This is the same speed ↔
abuse-resistance tradeoff measured in [`bench/rust`](bench/rust): SipHash costs
~1.8× to buy a stronger guarantee.

## Reproduce the benchmarks

```bash
# micro-benchmarks (in cache): here XXH3 is slightly faster than Murmur3
go test -run='^$' -bench='Benchmark' -benchmem -benchtime=3s

# end-to-end (out of cache): here blocking wins, not the hash
go run ./cmd/e2e/ -capacity 200000000 -fill 100 -blocked -tuned
```

Harness flags: `-capacity`, `-fill` (%), `-fp`, `-queries`, `-compare` (add
Murmur3), `-blocked`, `-tuned`.

A Rust cross-check that ports the same filters (to isolate language from
hash/algorithm, and to compare against the SipHash-based `bloomfilter` crate)
lives in [`bench/rust`](bench/rust). The false-positive counts match Go
bit-for-bit, and at an identical hash+algorithm Rust comes out ~1.2–1.6× ahead —
real but not order-of-magnitude, and smallest on the memory-bound query paths.

## Origin of the idea

The blocked Bloom filter is a well-known class, not our invention: see
Putze, Sanders & Singler, *"Cache-, Hash- and Space-Efficient Bloom Filters"* (2007).
Our contribution is a working Go implementation with automatic block-count tuning
for a target FP, serialization, and a reproducible harness that shows *exactly where*
the win comes from.

## Dependencies

- [`github.com/bits-and-blooms/bitset`](https://github.com/bits-and-blooms/bitset) — bit array for the classic tier (BSD-3)
- [`github.com/zeebo/xxh3`](https://github.com/zeebo/xxh3) — XXH3-128, the default hash (BSD-2)
- [`github.com/twmb/murmur3`](https://github.com/twmb/murmur3) — MurmurHash3-128 for `WithHash(Murmur3)` (BSD-3)
- [`github.com/bits-and-blooms/bloom/v3`](https://github.com/bits-and-blooms/bloom) — benchmark baseline only (BSD-3)

## License

MIT — see [LICENSE](LICENSE). Compatible with the BSD licenses of the dependencies
(all permissive). The blocked design follows the technique from Putze–Sanders–Singler
(2007); the implementation is original.
