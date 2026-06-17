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
	if want := int64(24 + src.Cap()/8); n != want {
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

func TestBlockedSerializationBadMagic(t *testing.T) {
	var f xxhbloom.BlockedFilter
	err := f.UnmarshalBinary([]byte("not a real filter blob................"))
	if err == nil {
		t.Fatal("expected error on bad magic, got nil")
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
