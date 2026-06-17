package bloom_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"testing"

	xxhbloom "github.com/ruslano69/xxh3-bloom"
	murbloom "github.com/bits-and-blooms/bloom/v3"
)

// ---- Correctness ----

func TestNoFalseNegatives(t *testing.T) {
	f := xxhbloom.NewWithEstimates(10_000, 0.01)
	buf := make([]byte, 8)
	keys := make([][]byte, 10_000)
	for i := range keys {
		binary.BigEndian.PutUint64(buf, uint64(i))
		keys[i] = append([]byte(nil), buf...)
		f.Add(keys[i])
	}
	for i, k := range keys {
		if !f.Test(k) {
			t.Fatalf("false negative at index %d", i)
		}
	}
}

func TestFalsePositiveRate(t *testing.T) {
	n := uint(100_000)
	target := 0.01
	f := xxhbloom.NewWithEstimates(n, target)

	buf := make([]byte, 4)
	for i := uint32(0); i < uint32(n); i++ {
		binary.BigEndian.PutUint32(buf, i)
		f.Add(buf)
	}

	rounds := 100_000
	fp := 0
	for i := 0; i < rounds; i++ {
		binary.BigEndian.PutUint32(buf, uint32(n)+uint32(i)+1)
		if f.Test(buf) {
			fp++
		}
	}
	rate := float64(fp) / float64(rounds)
	t.Logf("FP rate: %.4f  (target %.4f, m=%d, k=%d)", rate, target, f.Cap(), f.K())
	if rate > target*3 {
		t.Errorf("FP rate %.4f exceeds 3× target %.4f", rate, target)
	}
}

func TestBlockedNoFalseNegatives(t *testing.T) {
	f := xxhbloom.NewBlocked(10_000, 0.01)
	buf := make([]byte, 8)
	for i := 0; i < 10_000; i++ {
		binary.BigEndian.PutUint64(buf, uint64(i))
		f.Add(buf)
	}
	for i := 0; i < 10_000; i++ {
		binary.BigEndian.PutUint64(buf, uint64(i))
		if !f.Test(buf) {
			t.Fatalf("blocked false negative at %d", i)
		}
	}
}

func TestBlockedFalsePositiveRate(t *testing.T) {
	n := uint(100_000)
	target := 0.01
	f := xxhbloom.NewBlocked(n, target)
	buf := make([]byte, 4)
	for i := uint32(0); i < uint32(n); i++ {
		binary.BigEndian.PutUint32(buf, i)
		f.Add(buf)
	}
	rounds := 100_000
	fp := 0
	for i := 0; i < rounds; i++ {
		binary.BigEndian.PutUint32(buf, uint32(n)+uint32(i)+1)
		if f.Test(buf) {
			fp++
		}
	}
	rate := float64(fp) / float64(rounds)
	t.Logf("Blocked FP rate: %.4f (target %.4f, bits=%d, k=%d)", rate, target, f.Cap(), f.K())
	// blocked filters trade some FP accuracy for locality; allow up to 5x target
	if rate > target*5 {
		t.Errorf("blocked FP rate %.4f exceeds 5x target %.4f", rate, target)
	}
}

// TestBlockedTunedFPGridRegression is the release "lock" on the in-block probe
// scheme — the class of bug we found by calibration just before tagging, and the
// reason this test exists.
//
// Flawed double hashing (≤ v0.6.0) collapsed the k in-block probes onto a few
// residues, which FLOORED the achievable false-positive rate. It was invisible at
// fp=0.01 but ~3× over target at 0.001 and ~18× over at 0.0001 — a degeneration
// that grew as the target shrank. Enhanced double hashing removed that floor.
//
// Two things make this a real regression test rather than a single spot-check:
//  1. Grid coverage — a probabilistic floor only shows up at LOW targets, so the
//     sweep must reach 1e-4, not stop at 1e-2.
//  2. Statistical significance — the query count is scaled so each target sees a
//     fixed expected number of false positives (E[fp] ≈ wantFPCount), giving a
//     stable relative standard error (~1/sqrt(E[fp])). A rate measured from a
//     handful of hits proves nothing.
//
// The healthy enhanced scheme still overshoots at the extreme 1e-4 end (high k in
// a 512-bit block leaves few distinct residues), so there we do NOT assert
// accuracy we don't deliver — we assert only that it has not collapsed back to the
// old ~18× floor.
func TestBlockedTunedFPGridRegression(t *testing.T) {
	const n = uint(200_000)

	wantFPCount := 1500 // E[fp] per target ⇒ rel. std error ≈ 1/sqrt(1500) ≈ 2.6%
	if testing.Short() {
		wantFPCount = 300
	}

	cases := []struct {
		target float64
		margin float64 // measured rate must stay below target*margin
		note   string
	}{
		{0.05, 1.30, "supported, tight"},
		{0.01, 1.30, "supported, tight"},
		{0.005, 1.35, "supported, tight"},
		{0.001, 1.60, "supported; first target that exposed the flawed-hashing floor"},
		{0.0001, 6.0, "edge: tuned overshoots by design — guard only against the ~18× degeneration"},
	}

	buf := make([]byte, 8)
	for _, tc := range cases {
		f := xxhbloom.NewBlockedTuned(n, tc.target)
		for i := uint64(0); i < uint64(n); i++ {
			binary.BigEndian.PutUint64(buf, i)
			f.Add(buf)
		}

		rounds := int(float64(wantFPCount) / tc.target)
		if rounds < 500_000 {
			rounds = 500_000
		}
		fp := 0
		for i := 0; i < rounds; i++ {
			binary.BigEndian.PutUint64(buf, uint64(n)+uint64(i)+1)
			if f.Test(buf) {
				fp++
			}
		}

		rate := float64(fp) / float64(rounds)
		numBlocks := uint64(f.Cap()) / 512
		predicted := xxhbloom.EstimateBlockedFP(n, numBlocks, f.K())
		relErr := 0.0
		if fp > 0 {
			relErr = 100.0 / math.Sqrt(float64(fp))
		}
		t.Logf("target=%.4f k=%d rounds=%d predicted=%.6f measured=%.6f (%.2f× target, ±%.1f%% stderr) — %s",
			tc.target, f.K(), rounds, predicted, rate, rate/tc.target, relErr, tc.note)

		if fp < 100 {
			t.Fatalf("target=%.4f: only %d false positives observed — measurement not significant; raise rounds",
				tc.target, fp)
		}
		if rate > tc.target*tc.margin {
			t.Errorf("target=%.4f: measured FP %.6f exceeds %.2f× target (=%.6f) — the probe scheme may have regressed",
				tc.target, rate, tc.margin, tc.target*tc.margin)
		}
	}
}

func TestBlockedSerialization(t *testing.T) {
	src := xxhbloom.NewBlockedTuned(50_000, 0.01)
	buf := make([]byte, 8)
	for i := 0; i < 50_000; i++ {
		binary.BigEndian.PutUint64(buf, uint64(i))
		src.Add(buf)
	}

	// WriteTo / ReadFrom round-trip
	var b bytes.Buffer
	n, err := src.WriteTo(&b)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if want := int64(40 + src.Cap()/8); n != want {
		t.Fatalf("WriteTo wrote %d bytes, want %d", n, want)
	}

	dst := xxhbloom.NewBlocked(1, 0.5) // wrong shape on purpose
	if _, err := dst.ReadFrom(&b); err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if !src.Equal(dst) {
		t.Fatal("round-trip filters not equal")
	}

	// every inserted key must still test positive after reload
	for i := 0; i < 50_000; i++ {
		binary.BigEndian.PutUint64(buf, uint64(i))
		if !dst.Test(buf) {
			t.Fatalf("false negative after reload at %d", i)
		}
	}

	// MarshalBinary / UnmarshalBinary round-trip
	blob, err := src.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	var dst2 xxhbloom.BlockedFilter
	if err := dst2.UnmarshalBinary(blob); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}
	if !src.Equal(&dst2) {
		t.Fatal("MarshalBinary round-trip not equal")
	}
}

// Legacy formats v1–v4 used an incompatible probe scheme and must be rejected
// (not silently mis-read into false negatives).
func TestBlockedRejectsLegacyFormats(t *testing.T) {
	for _, version := range []byte{1, 2, 3, 4} {
		// header + a little payload; the body never gets parsed — the version
		// check fires first.
		var b bytes.Buffer
		b.Write([]byte{'B', 'B', 'L', 'M', version, 0, 0, 0})
		b.Write(make([]byte, 64)) // filler
		var f xxhbloom.BlockedFilter
		if err := f.UnmarshalBinary(b.Bytes()); err == nil {
			t.Fatalf("v%d: expected rejection, got nil error", version)
		}
	}
}

func TestBlockedSerializationBadMagic(t *testing.T) {
	var f xxhbloom.BlockedFilter
	err := f.UnmarshalBinary([]byte("not a real filter blob................"))
	if err == nil {
		t.Fatal("expected error on bad magic, got nil")
	}
}

func TestSeededNoFalseNegatives(t *testing.T) {
	seed := xxhbloom.RandomSeed()
	classic := xxhbloom.NewWithEstimatesAndSeed(20_000, 0.01, seed)
	blocked := xxhbloom.NewBlockedTunedWithSeed(20_000, 0.01, seed)
	buf := make([]byte, 8)
	for i := 0; i < 20_000; i++ {
		binary.BigEndian.PutUint64(buf, uint64(i))
		classic.Add(buf)
		blocked.Add(buf)
	}
	for i := 0; i < 20_000; i++ {
		binary.BigEndian.PutUint64(buf, uint64(i))
		if !classic.Test(buf) {
			t.Fatalf("seeded classic false negative at %d", i)
		}
		if !blocked.Test(buf) {
			t.Fatalf("seeded blocked false negative at %d", i)
		}
	}
	if classic.Seed() != seed || blocked.Seed() != seed {
		t.Fatal("Seed() did not report the configured seed")
	}
}

// Different seeds must produce different bit patterns for the same keys —
// that's exactly what defeats an attacker's precomputed collisions.
func TestSeedChangesBits(t *testing.T) {
	a := xxhbloom.NewBlockedWithSeed(10_000, 0.01, 1)
	b := xxhbloom.NewBlockedWithSeed(10_000, 0.01, 2)
	buf := make([]byte, 8)
	for i := 0; i < 10_000; i++ {
		binary.BigEndian.PutUint64(buf, uint64(i))
		a.Add(buf)
		b.Add(buf)
	}
	if a.Equal(b) {
		t.Fatal("filters with different seeds produced identical bits")
	}
	// seed 0 must reproduce the unseeded scheme exactly
	u1 := xxhbloom.NewBlocked(10_000, 0.01)
	u2 := xxhbloom.NewBlockedWithSeed(10_000, 0.01, 0)
	for i := 0; i < 10_000; i++ {
		binary.BigEndian.PutUint64(buf, uint64(i))
		u1.Add(buf)
		u2.Add(buf)
	}
	if !u1.Equal(u2) {
		t.Fatal("seed 0 should equal the unseeded filter")
	}
}

func TestSeededSerializationRoundTrip(t *testing.T) {
	seed := xxhbloom.RandomSeed()
	src := xxhbloom.NewBlockedTunedWithSeed(30_000, 0.01, seed)
	buf := make([]byte, 8)
	for i := 0; i < 30_000; i++ {
		binary.BigEndian.PutUint64(buf, uint64(i))
		src.Add(buf)
	}
	blob, err := src.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	var dst xxhbloom.BlockedFilter
	if err := dst.UnmarshalBinary(blob); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}
	if dst.Seed() != seed {
		t.Fatalf("seed not preserved: got %d, want %d", dst.Seed(), seed)
	}
	if !src.Equal(&dst) {
		t.Fatal("seeded round-trip not equal")
	}
	// keys must still test positive — proves the reloaded seed actually hashes right
	for i := 0; i < 30_000; i++ {
		binary.BigEndian.PutUint64(buf, uint64(i))
		if !dst.Test(buf) {
			t.Fatalf("false negative after seeded reload at %d", i)
		}
	}
}

func TestPluggableHashNoFalseNegatives(t *testing.T) {
	for _, kind := range []xxhbloom.HashKind{xxhbloom.XXH3, xxhbloom.Murmur3, xxhbloom.SipHash} {
		classic := xxhbloom.NewWithEstimates(20_000, 0.01, xxhbloom.WithHash(kind))
		blocked := xxhbloom.NewBlockedTuned(20_000, 0.01, xxhbloom.WithHash(kind), xxhbloom.WithSeed(7))
		buf := make([]byte, 8)
		for i := 0; i < 20_000; i++ {
			binary.BigEndian.PutUint64(buf, uint64(i))
			classic.Add(buf)
			blocked.Add(buf)
		}
		for i := 0; i < 20_000; i++ {
			binary.BigEndian.PutUint64(buf, uint64(i))
			if !classic.Test(buf) {
				t.Fatalf("%v classic false negative at %d", kind, i)
			}
			if !blocked.Test(buf) {
				t.Fatalf("%v blocked false negative at %d", kind, i)
			}
		}
		if classic.Hash() != kind || blocked.Hash() != kind {
			t.Fatalf("Hash() mismatch for %v", kind)
		}
	}
}

// Different hash → different bit pattern for the same keys.
func TestDifferentHashDiffersBits(t *testing.T) {
	a := xxhbloom.NewBlocked(10_000, 0.01, xxhbloom.WithHash(xxhbloom.XXH3))
	b := xxhbloom.NewBlocked(10_000, 0.01, xxhbloom.WithHash(xxhbloom.Murmur3))
	buf := make([]byte, 8)
	for i := 0; i < 10_000; i++ {
		binary.BigEndian.PutUint64(buf, uint64(i))
		a.Add(buf)
		b.Add(buf)
	}
	if a.Equal(b) {
		t.Fatal("XXH3 and Murmur3 produced identical bits")
	}
}

// Secured must bundle a seed + SipHash (the public-API recommendation).
func TestSecuredOption(t *testing.T) {
	f := xxhbloom.NewBlocked(1000, 0.01, xxhbloom.Secured(0x1234))
	if f.Hash() != xxhbloom.SipHash || f.Seed() != 0x1234 {
		t.Fatalf("Secured: hash=%v seed=%#x, want SipHash/0x1234", f.Hash(), f.Seed())
	}
	// a later explicit option still wins (options apply in order)
	g := xxhbloom.NewBlocked(1000, 0.01, xxhbloom.Secured(1), xxhbloom.WithHash(xxhbloom.XXH3))
	if g.Hash() != xxhbloom.XXH3 {
		t.Fatalf("later option should override Secured: got %v", g.Hash())
	}
}

// SipHash's DoS resistance comes from the secret seed: the same keys under two
// different seeds must land on different bits, or an attacker could precompute
// poisoning inputs regardless of the secret.
func TestSipHashSeedSeparation(t *testing.T) {
	a := xxhbloom.NewBlocked(10_000, 0.01, xxhbloom.WithHash(xxhbloom.SipHash), xxhbloom.WithSeed(0xA1))
	b := xxhbloom.NewBlocked(10_000, 0.01, xxhbloom.WithHash(xxhbloom.SipHash), xxhbloom.WithSeed(0xB2))
	buf := make([]byte, 8)
	for i := 0; i < 10_000; i++ {
		binary.BigEndian.PutUint64(buf, uint64(i))
		a.Add(buf)
		b.Add(buf)
	}
	if a.Equal(b) {
		t.Fatal("SipHash under different seeds produced identical bits")
	}
	// round-trips as v4 with hash + seed preserved
	blob, _ := a.MarshalBinary()
	if blob[4] != 5 {
		t.Fatalf("filter must serialize as v5, got %d", blob[4])
	}
	var dst xxhbloom.BlockedFilter
	if err := dst.UnmarshalBinary(blob); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}
	if dst.Hash() != xxhbloom.SipHash || dst.Seed() != 0xA1 {
		t.Fatalf("hash/seed not preserved: hash=%v seed=%#x", dst.Hash(), dst.Seed())
	}
}

// A Murmur3 filter must serialize as v4 and round-trip with the hash preserved.
func TestPluggableHashSerialization(t *testing.T) {
	src := xxhbloom.NewBlockedTuned(20_000, 0.01, xxhbloom.WithHash(xxhbloom.Murmur3), xxhbloom.WithSeed(99))
	buf := make([]byte, 8)
	for i := 0; i < 20_000; i++ {
		binary.BigEndian.PutUint64(buf, uint64(i))
		src.Add(buf)
	}
	blob, err := src.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if blob[4] != 5 {
		t.Fatalf("filter must serialize as v5, got version %d", blob[4])
	}
	var dst xxhbloom.BlockedFilter
	if err := dst.UnmarshalBinary(blob); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}
	if dst.Hash() != xxhbloom.Murmur3 || dst.Seed() != 99 {
		t.Fatalf("hash/seed not preserved: hash=%v seed=%d", dst.Hash(), dst.Seed())
	}
	if !src.Equal(&dst) {
		t.Fatal("Murmur3 round-trip not equal")
	}
	for i := 0; i < 20_000; i++ {
		binary.BigEndian.PutUint64(buf, uint64(i))
		if !dst.Test(buf) {
			t.Fatalf("false negative after Murmur3 reload at %d", i)
		}
	}
}

// All filters serialize as v5 now (the enhanced-probe format).
func TestWritesV5(t *testing.T) {
	f := xxhbloom.NewBlocked(5_000, 0.01)
	blob, _ := f.MarshalBinary()
	if blob[4] != 5 {
		t.Fatalf("filter must serialize as v5, got version %d", blob[4])
	}
}

// A registered custom hash round-trips; an unregistered kind fails to load.
func TestCustomHashRegistry(t *testing.T) {
	const myKind = xxhbloom.HashKind(200)
	// trivial custom hash (fine for a test; not for production)
	xxhbloom.RegisterHash(myKind, func(data []byte, seed uint64) (uint64, uint64) {
		var hi, lo uint64 = seed, 1469598103934665603
		for _, c := range data {
			lo = (lo ^ uint64(c)) * 1099511628211
			hi = (hi ^ lo) * 1099511628211
		}
		return hi, lo
	})

	src := xxhbloom.NewBlockedTuned(5_000, 0.01, xxhbloom.WithHash(myKind))
	buf := make([]byte, 8)
	for i := 0; i < 5_000; i++ {
		binary.BigEndian.PutUint64(buf, uint64(i))
		src.Add(buf)
	}
	blob, _ := src.MarshalBinary()

	var dst xxhbloom.BlockedFilter
	if err := dst.UnmarshalBinary(blob); err != nil {
		t.Fatalf("registered custom hash should load: %v", err)
	}
	if dst.Hash() != myKind {
		t.Fatalf("custom hash kind not preserved: %v", dst.Hash())
	}

	// Corrupt the kind byte to an unregistered value → load must fail cleanly.
	bad := append([]byte(nil), blob...)
	bad[9] = 201
	var dst2 xxhbloom.BlockedFilter
	if err := dst2.UnmarshalBinary(bad); err == nil {
		t.Fatal("expected error loading filter with unregistered hash kind")
	}
}

func TestTestAndAdd(t *testing.T) {
	f := xxhbloom.NewWithEstimates(1000, 0.01)
	key := []byte("hello-world")
	if f.TestAndAdd(key) {
		t.Fatal("expected false on first insert")
	}
	if !f.TestAndAdd(key) {
		t.Fatal("expected true on second insert")
	}
}

func ExampleFilter() {
	f := xxhbloom.NewWithEstimates(1000, 0.01)
	f.Add([]byte("hello"))
	f.Add([]byte("world"))
	fmt.Println(f.Test([]byte("hello")))
	fmt.Println(f.Test([]byte("definitely-not-in-filter-xyzzy-42")))
	// Output:
	// true
	// false
}

// ---- Benchmarks ----

// Three key lengths to show where XXH3 wins (longer = bigger gap).
var (
	keyShort  = []byte("550e8400e29b41d4")                                     // 16 B
	keyMedium = []byte("prod-bucket/users/42/uploads/summer_vacation.jpg")     // 52 B
	keyLong   = []byte(strings.Repeat("bucket/deeply/nested/path/segment/", 7)) // ~238 B
)

func BenchmarkMurmur3_Add_Short(b *testing.B) {
	f := murbloom.NewWithEstimates(1_000_000, 0.01)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.Add(keyShort)
	}
}

func BenchmarkXXH3_Add_Short(b *testing.B) {
	f := xxhbloom.NewWithEstimates(1_000_000, 0.01)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.Add(keyShort)
	}
}

func BenchmarkMurmur3_Add_Medium(b *testing.B) {
	f := murbloom.NewWithEstimates(1_000_000, 0.01)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.Add(keyMedium)
	}
}

func BenchmarkXXH3_Add_Medium(b *testing.B) {
	f := xxhbloom.NewWithEstimates(1_000_000, 0.01)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.Add(keyMedium)
	}
}

func BenchmarkMurmur3_Add_Long(b *testing.B) {
	f := murbloom.NewWithEstimates(1_000_000, 0.01)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.Add(keyLong)
	}
}

func BenchmarkXXH3_Add_Long(b *testing.B) {
	f := xxhbloom.NewWithEstimates(1_000_000, 0.01)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.Add(keyLong)
	}
}

func BenchmarkMurmur3_Test_Short(b *testing.B) {
	f := murbloom.NewWithEstimates(1_000_000, 0.01)
	f.Add(keyShort)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.Test(keyShort)
	}
}

func BenchmarkXXH3_Test_Short(b *testing.B) {
	f := xxhbloom.NewWithEstimates(1_000_000, 0.01)
	f.Add(keyShort)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.Test(keyShort)
	}
}

func BenchmarkMurmur3_Test_Long(b *testing.B) {
	f := murbloom.NewWithEstimates(1_000_000, 0.01)
	f.Add(keyLong)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.Test(keyLong)
	}
}

func BenchmarkXXH3_Test_Long(b *testing.B) {
	f := xxhbloom.NewWithEstimates(1_000_000, 0.01)
	f.Add(keyLong)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.Test(keyLong)
	}
}

func BenchmarkBlocked_Add_Short(b *testing.B) {
	f := xxhbloom.NewBlocked(1_000_000, 0.01)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.Add(keyShort)
	}
}

func BenchmarkBlocked_Test_Short(b *testing.B) {
	f := xxhbloom.NewBlocked(1_000_000, 0.01)
	f.Add(keyShort)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.Test(keyShort)
	}
}

func BenchmarkBlocked_Add_UniqueKeys(b *testing.B) {
	f := xxhbloom.NewBlocked(uint(b.N)+1000, 0.01)
	buf := make([]byte, 8)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		binary.LittleEndian.PutUint64(buf, uint64(i))
		f.Add(buf)
	}
}

// Realistic workload: unique 8-byte keys, filter growing.
func BenchmarkMurmur3_Add_UniqueKeys(b *testing.B) {
	f := murbloom.NewWithEstimates(uint(b.N)+1000, 0.01)
	buf := make([]byte, 8)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		binary.LittleEndian.PutUint64(buf, uint64(i))
		f.Add(buf)
	}
}

func BenchmarkXXH3_Add_UniqueKeys(b *testing.B) {
	f := xxhbloom.NewWithEstimates(uint(b.N)+1000, 0.01)
	buf := make([]byte, 8)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		binary.LittleEndian.PutUint64(buf, uint64(i))
		f.Add(buf)
	}
}
