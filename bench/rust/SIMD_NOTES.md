# SIMD playground — notes & next experiment

Scratch branch for SIMD experiments. Nothing here is part of the Go library API —
it all lives in `bench/rust`. Main already has two working modes:

- `simd`    — AVX2 split-block, 256-bit block (½ cache line), k=8. Mask built fully
              in-vector (`_mm256_mullo_epi32`). Fastest; FP ~1.52% at 1% target.
- `simd512` — AVX2 split-block, 512-bit block (one full cache line, 64B-aligned),
              8 lanes × 64 bits, k=8. **Mask built scalar** because AVX2 has no
              64-bit-lane multiply. FP ~1.28% (better), fill +37% / query +12–19%.

Measured (i7-7700, AVX2, 200M, same memory): see `README.md` → "Two registers per block".

## Next experiment: a real AVX-512 mode (for Zen 4 / Ryzen 9 7900X)

The point of `simd512` was held back by one AVX2 gap: no `_mm256_mullo_epi64`, so the
8 masks are computed scalar. AVX-512 fixes exactly that. Target: a single-register
512-bit block.

Building blocks (all present on Zen 4):
- `__m512i` block — one `_mm512_loadu_si512`, one OR, one store.
- `_mm512_mullo_epi64` (**AVX-512DQ**) — the 64-bit-lane multiply AVX2 lacked →
  build all 8 lane masks in-vector: `idx = (key64 * SALT64) >> 58`, then
  `_mm512_sllv_epi64(set1(1), idx)` (AVX-512F).
- Containment test (no `testc` in AVX-512): `t = _mm512_andnot_si512(block, mask)`
  (bits required but missing); `_mm512_test_epi64_mask(t, t) == 0` ⇒ contained.

Plumbing:
- `target_feature(enable = "avx512f,avx512dq")`; gate at construction with
  `is_x86_feature_detected!("avx512f") && is_x86_feature_detected!("avx512dq")`.
- Rust 1.95 has stable AVX-512 intrinsics — no nightly needed.
- Add as a new `--mode avx512` next to `simd`/`simd512` in `main.rs` (mirror
  `SimdBlocked512`, swap the scalar mask build for the vector one above).

Hypothesis to test on the 7900X:
- `avx512` should beat AVX2 `simd512` **mainly via the vectorized mask build**, not
  via raw 512-bit ALU width — Zen 4 double-pumps AVX-512 (256-bit physical units),
  so 512-bit ops are ~2 cycles. The lookup path is memory-latency-bound anyway, so
  expect the bigger win on the throughput-bound **fill** path.
- Cache line on Zen 4 is 64B (like all x86), so 512-bit block = 1 line — geometry holds.

⚠️ Correctness was NOT validated on the dev machine (i7-7700 can't execute AVX-512 —
it SIGILLs). On the first Zen 4 run, check no-false-negatives and FP before trusting
any timing. Compare back-to-back in one run (shared machine state) — see the
methodology note in `README.md`.
