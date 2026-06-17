# Cache-penetration defense (example)

Defends a Redis-backed service against a **cache-penetration** attack — a flood
of queries for keys that don't exist, crafted to miss the cache and hammer the
expensive backend — using an in-process Bloom filter.

Fully self-contained: it runs an **embedded [miniredis](https://github.com/alicebob/miniredis)**,
so there's no Docker, no network, and the "attack" only ever touches localhost.
This is a **separate Go module** so its test dependencies (miniredis, go-redis)
do not leak into the library's dependency graph.

```
go run .
```

## What it shows

```
WITHOUT guard: redis GETs=500000  backend hits=500000  time=39s
WITH guard   : redis GETs=1607    backend hits=1607    time=257ms
Backend hits cut: 500000 -> 1607  (99.7% of the flood blocked before it left the process)
Legit keys wrongly blocked: 0 (must be 0 — Bloom has no false negatives)
```

- The guard rejects definitely-absent keys **before any I/O** — Redis and the
  backend are never touched, and the flood is handled ~150× faster because it
  never reaches the network.
- A small fraction (the false-positive rate) still slips through; in production
  pair the filter with rate-limiting and negative caching.

## Why `Secured`

The attacker chooses the keys, so this is the **public / untrusted** trust
boundary. The guard therefore uses `bloom.Secured(bloom.RandomSeed())` — a secret
seed plus SipHash. An *unseeded* filter could be defeated: knowing the fixed hash,
an attacker precomputes absent keys that the filter false-positives on, slipping
straight past the defense. The secret seed makes those collisions unpredictable.

## Notes / honest limits

- This guards the **backend behind Redis**, and placing the filter in app memory
  also saves the round-trip to Redis itself. A filter living *inside* Redis
  (RedisBloom) still costs a network hop per check.
- Standard Bloom filters can't delete: if keys are removed from the backend, the
  filter still reports "maybe present" for them. For a churning keyspace, rebuild
  periodically or use a counting/cuckoo filter.
- At a very low target FP (here 0.001) the tuned sizing model is optimistic and
  the measured rate can run a few× over target; for a hard guarantee, oversize or
  measure against your real keyset.
