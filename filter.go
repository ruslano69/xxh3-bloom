package bloom

import (
	"crypto/rand"
	"encoding/binary"
	"math"

	"github.com/bits-and-blooms/bitset"
)

// Filter is a Bloom filter. By default it hashes with XXH3; a non-zero seed
// turns the hash into a keyed function (see WithSeed and the threat-model notes
// in the README), and WithHash selects a different hash entirely.
type Filter struct {
	m      uint
	k      uint
	seed   uint64
	hash   HashKind
	hasher Hasher
	b      *bitset.BitSet
}

func maxU(x, y uint) uint {
	if x > y {
		return x
	}
	return y
}

// RandomSeed returns a cryptographically random seed suitable for WithSeed.
// Generate one per process (or per filter) and keep it secret.
func RandomSeed() uint64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("bloom: crypto/rand failed: " + err.Error())
	}
	return binary.LittleEndian.Uint64(b[:])
}

// New returns a Filter with m bits and k hash functions, configured by opts.
func New(m, k uint, opts ...Option) *Filter {
	return newFilter(m, k, buildConfig(opts))
}

func newFilter(m, k uint, c config) *Filter {
	h, err := resolveHasher(c.hash)
	if err != nil {
		panic(err) // an unknown hash at construction time is a programmer error
	}
	return &Filter{maxU(1, m), maxU(1, k), c.seed, c.hash, h, bitset.New(m)}
}

// NewWithEstimates returns a Filter sized for n items at false-positive rate fp,
// configured by opts.
func NewWithEstimates(n uint, fp float64, opts ...Option) *Filter {
	m, k := EstimateParameters(n, fp)
	return New(m, k, opts...)
}

// NewWithSeed is shorthand for New(m, k, WithSeed(seed)).
//
// Deprecated: use New(m, k, WithSeed(seed)).
func NewWithSeed(m, k uint, seed uint64) *Filter {
	return New(m, k, WithSeed(seed))
}

// NewWithEstimatesAndSeed is shorthand for NewWithEstimates(n, fp, WithSeed(seed)).
//
// Deprecated: use NewWithEstimates(n, fp, WithSeed(seed)).
func NewWithEstimatesAndSeed(n uint, fp float64, seed uint64) *Filter {
	return NewWithEstimates(n, fp, WithSeed(seed))
}

// EstimateParameters returns optimal m (bits) and k (hash count) for n items at false-positive rate fp.
func EstimateParameters(n uint, fp float64) (m, k uint) {
	m = uint(math.Ceil(-1 * float64(n) * math.Log(fp) / math.Pow(math.Log(2), 2)))
	k = uint(math.Ceil(math.Log(2) * float64(m) / float64(n)))
	return
}

// baseHashes returns 4 independent uint64 values from two keyed 128-bit hashes.
// Consecutive seeds give two unrelated hash functions over the same input.
func (f *Filter) baseHashes(data []byte) [4]uint64 {
	aHi, aLo := f.hasher(data, f.seed)
	bHi, bLo := f.hasher(data, f.seed+1)
	return [4]uint64{aLo, aHi, bLo, bHi}
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
	h := f.baseHashes(data)
	for i := uint(0); i < f.k; i++ {
		f.b.Set(f.loc(h, i))
	}
	return f
}

// Test returns true if data is possibly in the filter, false if definitely absent.
func (f *Filter) Test(data []byte) bool {
	h := f.baseHashes(data)
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
	h := f.baseHashes(data)
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

// Seed returns the hashing seed (0 means unseeded).
func (f *Filter) Seed() uint64 { return f.seed }

// Hash returns the hash function the filter uses.
func (f *Filter) Hash() HashKind { return f.hash }
