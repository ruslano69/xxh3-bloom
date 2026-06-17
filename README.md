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
a := uint32(h.Lo)              // low 64 bits, lower half
b := uint32(h.Lo>>32) | 1      //              upper half (odd stride)
// k positions inside the block via enhanced double hashing (Dillinger-Manolios):
//   bit_i = a & 511; then a += b; b += i
```

So from one hash we get both the **block index** and the two seeds for the in-block
probe sequence for free — no second pass over the data, no heap. The classic
`bits-and-blooms` runs Murmur3-128 twice for this (see `sum256`); one `Hash128` is
enough for us. That's a simplification, not a faster hash.

The probe sequence is **enhanced double hashing** (an odd stride plus a triangular
term). Plain double hashing `a + i*b mod 512` collides badly when the stride shares
factors with the power-of-two block size — exactly the
[flaw RocksDB hit](https://github.com/facebook/rocksdb/issues/4120) — which floors
the false-positive rate at high `k`. The enhanced sequence keeps the `k` probes
distinct, so the blocked tiers hit their target FP down to ~0.001.

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

Built-in hashes, selected with `WithHash`:

| Kind | What | When |
|---|---|---|
| `XXH3` (default) | fast, alloc-free 128-bit | trusted keys, max speed |
| `Murmur3` | MurmurHash3-128 | matches `bits-and-blooms` scheme |
| `SipHash` | SipHash-2-4, keyed PRF | untrusted keys — DoS-resistant **with** `WithSeed` |

You can also register your own with `RegisterHash(kind, hasher)` (kind ≥ 128).
The chosen hash is recorded in the serialized form, so a filter always reloads
with the hash it was built with.

⚠️ **Selecting `Murmur3` matches the hash used by `bits-and-blooms/bloom`, but
that alone does not make the filters bit-compatible** — true interop also requires
the same location formula, bit layout, and m/k rounding. Treat `WithHash` as
"choose the hashing primitive," not "drop-in interop with library X."

Picking a tier (by resources):

```
Memory-constrained, accuracy critical   → Filter (classic)
Have RAM, need throughput               → NewBlockedTuned
Accuracy not critical, want raw speed   → NewBlocked
```

### Choosing by trust boundary

The security config follows one rule: **who supplies the keys?** Speed is safe
for internal APIs — pick the fastest tier at adequate accuracy. Switch to the
secured variant the moment keys come from a published, externally reachable
surface.

| Keys come from | Use | Why |
|---|---|---|
| **Internal** — IDs you generate, file paths, cache keys | default (XXH3, unseeded) | nothing to attack; take the speed |
| **Public** — anything an external caller chooses | `Secured(RandomSeed())` | a known hash can be poisoned; key it |

```go
// Internal API: fastest path
f := bloom.NewBlockedTuned(n, fp)

// Public API: keyed + SipHash in one option
f := bloom.NewBlockedTuned(n, fp, bloom.Secured(bloom.RandomSeed()))
```

`Secured` is shorthand for `WithSeed(seed) + WithHash(SipHash)`. If you only need
to defeat offline precomputation cheaply (and skip SipHash's cost), use
`WithSeed(secret)` alone — see [Security](#security-hashing-seed--threat-model).

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
take minutes through `binary.Write`). The current format **v5** is self-describing:
it records the seed, hash kind, and the payload's byte order, so `WriteTo` always
writes at host speed and `ReadFrom` byte-swaps only on the rare cross-endian load
— **v5 files are portable**.

⚠️ **Formats v1–v4 (`≤ v0.6.0`) are rejected.** They used a flawed in-block probe
scheme with a different bit layout (see below); reinterpreting them under v5 would
produce false negatives, so `ReadFrom` refuses them with a clear error rather than
silently corrupting results. A Bloom filter can't be rebuilt from its bits, so such
filters must be **regenerated from source data**.

| Format | Header | Stores | Status |
|---|---|---|---|
| v1–v4 (`≤ v0.6.0`) | 24–40 B | — | **rejected** (incompatible probe scheme) |
| v5 (`v0.7.0`) | 40 B | endianness, hash kind, seed | current, portable |

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

Two levels of mitigation, both via `WithSeed(RandomSeed())`:

```go
// Good: XXH3 keyed by a secret seed — defeats offline precomputation, fast.
bloom.NewBlockedTuned(n, fp, bloom.WithSeed(secret))

// Stronger: SipHash, a keyed cryptographic PRF — the conservative choice.
bloom.NewBlockedTuned(n, fp, bloom.WithSeed(secret), bloom.WithHash(bloom.SipHash))
```

```
Keys are YOUR data (file paths, internal IDs you generate)   → unseeded is fine
Untrusted keys, want speed                                   → XXH3 + WithSeed
Untrusted keys, want the rigorous guarantee                  → SipHash + WithSeed
```

**Why two levels.** Seeded XXH3 defeats *offline* collision precomputation,
which covers the practical threat cheaply. But XXH3 is not a proven crypto
primitive: against a determined adversary mounting *adaptive online* attacks,
`SipHash` (a keyed PRF, the same family Rust/Python hash maps use) is the
conservative choice. SipHash is slower — the speed ↔ abuse-resistance tradeoff
measured in [`bench/rust`](bench/rust) (~1.8×) — but now it's a one-line option
rather than a different library. **SipHash without a seed gives no DoS
resistance** — the seed is its key.

A runnable end-to-end demo of this — defending a Redis-backed service from a
cache-penetration flood, against an embedded miniredis (no Docker) — lives in
[`examples/cache-penetration`](examples/cache-penetration). It blocks 99.7% of a
500k-key attack before it leaves the process.

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
- [`github.com/dchest/siphash`](https://github.com/dchest/siphash) — SipHash-2-4-128 for `WithHash(SipHash)` (CC0)
- [`github.com/bits-and-blooms/bloom/v3`](https://github.com/bits-and-blooms/bloom) — benchmark baseline only (BSD-3)

## License

MIT — see [LICENSE](LICENSE). Compatible with the BSD licenses of the dependencies
(all permissive). The blocked design follows the technique from Putze–Sanders–Singler
(2007); the implementation is original.
