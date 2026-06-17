package bloom

import (
	"math"

	"github.com/bits-and-blooms/bitset"
	"github.com/zeebo/xxh3"
)

// Filter is a Bloom filter using xxh3-128 for hashing instead of MurmurHash3.
// API mirrors github.com/bits-and-blooms/bloom/v3.
type Filter struct {
	m uint
	k uint
	b *bitset.BitSet
}

func maxU(x, y uint) uint {
	if x > y {
		return x
	}
	return y
}

// New returns a Filter with m bits and k hash functions.
func New(m, k uint) *Filter {
	return &Filter{maxU(1, m), maxU(1, k), bitset.New(m)}
}

// NewWithEstimates returns a Filter sized for n items at false-positive rate fp.
func NewWithEstimates(n uint, fp float64) *Filter {
	m, k := EstimateParameters(n, fp)
	return New(m, k)
}

// EstimateParameters returns optimal m (bits) and k (hash count) for n items at false-positive rate fp.
func EstimateParameters(n uint, fp float64) (m, k uint) {
	m = uint(math.Ceil(-1 * float64(n) * math.Log(fp) / math.Pow(math.Log(2), 2)))
	k = uint(math.Ceil(math.Log(2) * float64(m) / float64(n)))
	return
}

// baseHashes returns 4 independent uint64 values using two XXH3-128 calls.
// Seed 0 and seed 1 give two unrelated hash functions over the same input.
// This is a drop-in replacement for the MurmurHash3-based baseHashes in bits-and-blooms.
func baseHashes(data []byte) [4]uint64 {
	a := xxh3.Hash128(data)
	b := xxh3.Hash128Seed(data, 1)
	return [4]uint64{a.Lo, a.Hi, b.Lo, b.Hi}
}

// location computes the i-th bit index from the 4 base hashes.
// Identical formula to bits-and-blooms/bloom.
func location(h [4]uint64, i uint) uint64 {
	ii := uint64(i)
	return h[ii%2] + ii*h[2+(((ii+(ii%2))%4)/2)]
}

func (f *Filter) loc(h [4]uint64, i uint) uint {
	return uint(location(h, i) % uint64(f.m))
}

// Add inserts data into the filter. Returns f for chaining.
func (f *Filter) Add(data []byte) *Filter {
	h := baseHashes(data)
	for i := uint(0); i < f.k; i++ {
		f.b.Set(f.loc(h, i))
	}
	return f
}

// Test returns true if data is possibly in the filter, false if definitely absent.
func (f *Filter) Test(data []byte) bool {
	h := baseHashes(data)
	for i := uint(0); i < f.k; i++ {
		if !f.b.Test(f.loc(h, i)) {
			return false
		}
	}
	return true
}

// TestAndAdd tests membership then unconditionally sets bits. Returns previous membership.
func (f *Filter) TestAndAdd(data []byte) bool {
	present := true
	h := baseHashes(data)
	for i := uint(0); i < f.k; i++ {
		l := f.loc(h, i)
		if !f.b.Test(l) {
			present = false
		}
		f.b.Set(l)
	}
	return present
}

// Cap returns m (capacity in bits).
func (f *Filter) Cap() uint { return f.m }

// K returns the number of hash functions.
func (f *Filter) K() uint { return f.k }
