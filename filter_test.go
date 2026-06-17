package bloom_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
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

func TestBlockedTunedMeetsTarget(t *testing.T) {
	n := uint(200_000)
	target := 0.01
	f := xxhbloom.NewBlockedTuned(n, target)

	buf := make([]byte, 4)
	for i := uint32(0); i < uint32(n); i++ {
		binary.BigEndian.PutUint32(buf, i)
		f.Add(buf)
	}
	rounds := 200_000
	fp := 0
	for i := 0; i < rounds; i++ {
		binary.BigEndian.PutUint32(buf, uint32(n)+uint32(i)+1)
		if f.Test(buf) {
			fp++
		}
	}
	rate := float64(fp) / float64(rounds)
	numBlocks := uint64(f.Cap()) / 512
	predicted := xxhbloom.EstimateBlockedFP(n, numBlocks, f.K())
	t.Logf("tuned: bits=%d k=%d  predicted FP=%.4f  measured FP=%.4f  (target %.4f)",
		f.Cap(), f.K(), predicted, rate, target)
	if rate > target*1.15 {
		t.Errorf("tuned FP %.4f exceeds target %.4f (×1.15 margin)", rate, target)
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

// ReadFrom must still load legacy v1 (no seed) and v2 (with seed) files.
func TestBlockedReadsLegacyFormats(t *testing.T) {
	// build a populated unseeded filter and grab its raw payload (v3 blob tail)
	mk := func(seed uint64) ([]byte, uint64, uint, uint64) {
		f := xxhbloom.NewBlockedTunedWithSeed(5_000, 0.01, seed)
		buf := make([]byte, 8)
		for i := 0; i < 5_000; i++ {
			binary.BigEndian.PutUint64(buf, uint64(i))
			f.Add(buf)
		}
		v3, _ := f.MarshalBinary()
		payload := v3[40:] // strip v3 header
		return payload, uint64(f.Cap()) / 512, f.K(), seed
	}

	check := func(name string, blob []byte, wantSeed uint64) {
		var f xxhbloom.BlockedFilter
		if err := f.UnmarshalBinary(blob); err != nil {
			t.Fatalf("%s: UnmarshalBinary: %v", name, err)
		}
		if f.Seed() != wantSeed {
			t.Fatalf("%s: seed = %d, want %d", name, f.Seed(), wantSeed)
		}
		buf := make([]byte, 8)
		for i := 0; i < 5_000; i++ {
			binary.BigEndian.PutUint64(buf, uint64(i))
			if !f.Test(buf) {
				t.Fatalf("%s: false negative at %d after legacy load", name, i)
			}
		}
	}

	// v1: 24-byte header, no seed → must load with seed 0
	payload, numBlocks, k, _ := mk(0)
	var v1 bytes.Buffer
	v1.Write([]byte{'B', 'B', 'L', 'M', 1, 0, 0, 0})
	writeLE(&v1, numBlocks)
	writeLE(&v1, uint64(k))
	v1.Write(payload)
	check("v1", v1.Bytes(), 0)

	// v2: 32-byte header with seed
	const seed2 = 0xDEADBEEFCAFE
	payload, numBlocks, k, _ = mk(seed2)
	var v2 bytes.Buffer
	v2.Write([]byte{'B', 'B', 'L', 'M', 2, 0, 0, 0})
	writeLE(&v2, numBlocks)
	writeLE(&v2, uint64(k))
	writeLE(&v2, seed2)
	v2.Write(payload)
	check("v2", v2.Bytes(), seed2)
}

func writeLE(buf *bytes.Buffer, v uint64) {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	buf.Write(b[:])
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
	if blob[4] != 4 {
		t.Fatalf("SipHash filter must serialize as v4, got %d", blob[4])
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
	if blob[4] != 4 {
		t.Fatalf("non-XXH3 filter must serialize as v4, got version %d", blob[4])
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

// XXH3 filters must still serialize as v3 (back-compat with v0.3.0 readers).
func TestXXH3StillWritesV3(t *testing.T) {
	f := xxhbloom.NewBlocked(5_000, 0.01)
	blob, _ := f.MarshalBinary()
	if blob[4] != 3 {
		t.Fatalf("XXH3 filter must serialize as v3, got version %d", blob[4])
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
