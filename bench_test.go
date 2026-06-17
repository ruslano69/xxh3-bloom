package bloom_test

import (
	"encoding/binary"
	"strings"
	"testing"

	murbloom "github.com/bits-and-blooms/bloom/v3"
	xxhbloom "github.com/ruslano69/xxh3-bloom"
)

// All Benchmark* live here, in the external test package: every one uses only
// the exported API, so they don't need package internals. Correctness Test*
// (which do reach into unexported fields) stay in their filter_*_test.go files.

const benchN = 20_000_000

func key8(i int) []byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], uint64(i))
	return b[:]
}

// Three key lengths to show where XXH3 wins (longer = bigger gap).
var (
	keyShort  = []byte("550e8400e29b41d4")                                      // 16 B
	keyMedium = []byte("prod-bucket/users/42/uploads/summer_vacation.jpg")      // 52 B
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

func benchBlocked(b *testing.B) (*xxhbloom.BlockedFilter, [][]byte) {
	b.Helper()
	f := xxhbloom.NewBlocked(benchN, 0.01)
	keys := make([][]byte, benchN)
	for i := range keys {
		keys[i] = key8(i)
		f.Add(keys[i])
	}
	return f, keys
}

func BenchmarkBlockedTestLoop(b *testing.B) {
	f, keys := benchBlocked(b)
	out := make([]bool, len(keys))
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		for i, k := range keys {
			out[i] = f.Test(k)
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(b.N*len(keys)), "ops")
}

func BenchmarkBlockedTestBatch(b *testing.B) {
	f, keys := benchBlocked(b)
	out := make([]bool, len(keys))
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		f.TestBatch(keys, out)
	}
	b.StopTimer()
	b.ReportMetric(float64(b.N*len(keys)), "ops")
}

func benchSimd(b *testing.B) (*xxhbloom.SimdFilter, [][]byte) {
	b.Helper()
	f := xxhbloom.NewSimd(benchN, 0.01)
	keys := make([][]byte, benchN)
	for i := range keys {
		keys[i] = key8(i)
		f.Add(keys[i])
	}
	return f, keys
}

func BenchmarkSimdTestLoop(b *testing.B) {
	f, keys := benchSimd(b)
	out := make([]bool, len(keys))
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		for i, k := range keys {
			out[i] = f.Test(k)
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(b.N*len(keys)), "ops")
}

func BenchmarkSimdTestBatch(b *testing.B) {
	f, keys := benchSimd(b)
	out := make([]bool, len(keys))
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		f.TestBatch(keys, out)
	}
	b.StopTimer()
	b.ReportMetric(float64(b.N*len(keys)), "ops")
}

func BenchmarkSimdAddLoop(b *testing.B) {
	keys := make([][]byte, benchN)
	for i := range keys {
		keys[i] = key8(i)
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		f := xxhbloom.NewSimd(benchN, 0.01)
		for _, k := range keys {
			f.Add(k)
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(b.N*len(keys)), "ops")
}

func BenchmarkSimdAddBatch(b *testing.B) {
	keys := make([][]byte, benchN)
	for i := range keys {
		keys[i] = key8(i)
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		f := xxhbloom.NewSimd(benchN, 0.01)
		f.AddBatch(keys)
	}
	b.StopTimer()
	b.ReportMetric(float64(b.N*len(keys)), "ops")
}
