package bloom

import (
	"math"
	"unsafe"
)

// A SimdFilter is a split-block (register-blocked) Bloom filter in the
// Impala/Parquet style: each block is 256 bits viewed as 8 lanes of 32 bits,
// and exactly one bit is set per lane (so k is fixed at 8). One hash picks the
// block; the low 32 bits of the same hash derive all 8 lane positions. Like the
// scalar BlockedFilter it touches one block per op, but the block is half a
// cache line and the whole membership test is a handful of word ops — which on
// amd64 maps directly to ~5 AVX2 instructions (added separately).
//
// This file is the SCALAR reference: it defines the bit layout. Any vectorized
// path must produce byte-for-byte identical blocks (guarded by a test).
//
// Tradeoff vs the scalar 512-bit blocked filter: one-bit-per-32-bit-lane
// constrains bit placement, so for equal memory the false-positive rate is a
// little higher. It is an experiment, not (yet) part of the stable API.

const (
	simdLanes     = 8              // 32-bit lanes per block
	simdBlockBits = simdLanes * 32 // 256 bits = half a cache line
	simdK         = simdLanes      // one bit set per lane
	simdIdxShift  = 27             // top 5 bits of the 32-bit product -> 0..31
)

// simdSalt are the per-lane multipliers (odd 32-bit constants). They must match
// the Rust reference (bench/rust) so the two implementations lay out identical
// bits for the same hash.
var simdSalt = [simdLanes]uint32{
	0x47b6137b, 0x44974d91, 0x8824ad5b, 0xa2b7289d,
	0x705495c7, 0x2df1424c, 0x9efc4947, 0x5c6bfb31,
}

type SimdFilter struct {
	backing   []uint32 // numBlocks * simdLanes, contiguous (one block = 8 u32)
	numBlocks uint64
	seed      uint64
	hash      HashKind
	hasher    Hasher
}

// NewSimd builds a 256-bit split-block filter sized to roughly the same memory
// as NewBlocked for the same n/fp. k is fixed at 8 (one bit per lane), so fp is
// only used to size the block count. Like NewBlocked, the *measured* FP runs a
// little above fp because of uneven per-block load (here ~1.5% at a 1% target);
// use NewSimdTuned to hit the target at the cost of more memory.
func NewSimd(n uint, fp float64, opts ...Option) *SimdFilter {
	c := buildConfig(opts)
	m, _ := EstimateParameters(n, fp)
	numBlocks := uint64(math.Ceil(float64(m) / simdBlockBits))
	return allocSimd(numBlocks, c)
}

// NewSimdTuned builds a split-block filter whose *measured* FP at n items is
// <= fp, by inflating the block count to compensate for uneven per-block load
// and the one-bit-per-lane layout. It costs ~15% more memory than NewSimd for a
// 1% target (a bit more than NewBlockedTuned's ~10%, the price of the split-block
// layout), and keeps the SIMD speed.
func NewSimdTuned(n uint, fp float64, opts ...Option) *SimdFilter {
	c := buildConfig(opts)
	if n == 0 {
		n = 1
	}
	// EstimateSimdFP is mildly optimistic (it treats the 8 lane probes as
	// independent); tune against a stricter internal target so the measured
	// rate lands at/under fp. 0.85 was fitted to the empirical sweep.
	const safety = 0.85
	numBlocks := minSimdBlocks(n, fp*safety)
	return allocSimd(numBlocks, c)
}

// allocSimd resolves the hasher (panicking on an unknown hash — a construction
// -time programmer error) and allocates the backing store.
func allocSimd(numBlocks uint64, c config) *SimdFilter {
	h, err := resolveHasher(c.hash)
	if err != nil {
		panic(err)
	}
	if numBlocks < 1 {
		numBlocks = 1
	}
	return &SimdFilter{
		backing:   make([]uint32, numBlocks*simdLanes),
		numBlocks: numBlocks,
		seed:      c.seed,
		hash:      c.hash,
		hasher:    h,
	}
}

// EstimateSimdFP estimates the false-positive rate of a split-block filter with
// numBlocks blocks of simdLanes lanes (one bit set per 32-bit lane). Keys land
// in blocks following Poisson(lambda), lambda = n/numBlocks; a block holding j
// keys has per-lane occupancy 1-(1-1/32)^j, and a false positive requires all
// simdLanes lanes to match. We average that over the Poisson load.
func EstimateSimdFP(n uint, numBlocks uint64) float64 {
	if numBlocks < 1 {
		numBlocks = 1
	}
	lambda := float64(n) / float64(numBlocks)
	if lambda > 4000 { // hopelessly overloaded => FP ~ 1
		return 1.0
	}
	const bitsPerLane = 32.0
	hi := int(lambda + 10*math.Sqrt(lambda) + 10)
	sum := 0.0
	logLambda := math.Log(lambda)
	logPmf := -lambda // log P(j=0)
	for j := 0; j <= hi; j++ {
		if j > 0 {
			logPmf += logLambda - math.Log(float64(j))
		}
		pmf := math.Exp(logPmf)
		perLane := 1 - math.Pow(1-1/bitsPerLane, float64(j))
		sum += pmf * math.Pow(perLane, simdLanes)
	}
	return sum
}

// minSimdBlocks returns the fewest blocks whose estimated FP at n items is <=
// fp. FP falls monotonically as blocks grow (lower per-block load), so we
// binary-search.
func minSimdBlocks(n uint, fp float64) uint64 {
	fpAt := func(nb uint64) float64 { return EstimateSimdFP(n, nb) }
	hi := uint64(1)
	for fpAt(hi) > fp {
		hi *= 2
		if hi > (1 << 42) { // safety: ~4.5e12 blocks
			break
		}
	}
	lo := hi / 2
	if lo < 1 {
		lo = 1
	}
	for lo < hi {
		mid := lo + (hi-lo)/2
		if fpAt(mid) <= fp {
			hi = mid
		} else {
			lo = mid + 1
		}
	}
	return lo
}

// hashParts derives the block's base index in backing and the 32-bit key that
// seeds the 8 lane positions. Shared by the scalar and AVX2 paths so both pick
// the same block and mask.
func (f *SimdFilter) hashParts(data []byte) (base uint64, key32 uint32) {
	hi, lo := f.hasher(data, f.seed)
	block := hi % f.numBlocks // modulo, matching the Rust simd reference
	return block * simdLanes, uint32(lo)
}

// simdMaskScalar builds the 8 per-lane masks (one bit each). It defines the bit
// layout; the AVX2 path must produce identical lanes (guarded by a test).
func simdMaskScalar(key32 uint32) (mask [simdLanes]uint32) {
	for l := 0; l < simdLanes; l++ {
		idx := (key32 * simdSalt[l]) >> simdIdxShift // 0..31
		mask[l] = 1 << idx
	}
	return
}

// setScalarAt / testScalarAt apply an already-located (block, key) without
// re-hashing. They are the portable fallback for setAt/testAt and the
// bit-exactness reference in tests.
func (f *SimdFilter) setScalarAt(base uint64, key32 uint32) {
	mask := simdMaskScalar(key32)
	for l := 0; l < simdLanes; l++ {
		f.backing[base+uint64(l)] |= mask[l]
	}
}

func (f *SimdFilter) testScalarAt(base uint64, key32 uint32) bool {
	mask := simdMaskScalar(key32)
	for l := 0; l < simdLanes; l++ {
		if f.backing[base+uint64(l)]&mask[l] != mask[l] {
			return false
		}
	}
	return true
}

// addScalar / testScalar are the scalar hash+apply used as the test reference.
func (f *SimdFilter) addScalar(data []byte) *SimdFilter {
	base, key32 := f.hashParts(data)
	f.setScalarAt(base, key32)
	return f
}

func (f *SimdFilter) testScalar(data []byte) bool {
	base, key32 := f.hashParts(data)
	return f.testScalarAt(base, key32)
}

// Add inserts data. Touches one 256-bit block. setAt picks the AVX2 or scalar
// apply for the build platform.
func (f *SimdFilter) Add(data []byte) *SimdFilter {
	base, key32 := f.hashParts(data)
	f.setAt(base, key32)
	return f
}

// Test reports possible membership. Touches one 256-bit block.
func (f *SimdFilter) Test(data []byte) bool {
	base, key32 := f.hashParts(data)
	return f.testAt(base, key32)
}

// simdBatchProbe carries the located block + key from the hash/prefetch phase to
// the apply phase, so the apply pass does not re-hash.
type simdBatchProbe struct {
	base  uint64
	key32 uint32
}

// AddBatch inserts every key in data. It hashes and software-prefetches a window
// of blocks before touching them, keeping several cache misses in flight (MLP)
// on the throughput-bound fill path — where the vectorized mask helps most.
func (f *SimdFilter) AddBatch(data [][]byte) {
	var probe [batchWindow]simdBatchProbe
	for start := 0; start < len(data); start += batchWindow {
		end := start + batchWindow
		if end > len(data) {
			end = len(data)
		}
		n := end - start
		for j := 0; j < n; j++ {
			b, k := f.hashParts(data[start+j])
			prefetchT0(unsafe.Pointer(&f.backing[b]))
			probe[j] = simdBatchProbe{b, k}
		}
		for j := 0; j < n; j++ {
			f.setAt(probe[j].base, probe[j].key32)
		}
	}
}

// TestBatch reports membership for each key in data, writing data[i]'s answer to
// out[i] (out must have len >= len(data)). Like AddBatch it prefetches a window
// ahead so several blocks load in parallel.
func (f *SimdFilter) TestBatch(data [][]byte, out []bool) {
	var probe [batchWindow]simdBatchProbe
	for start := 0; start < len(data); start += batchWindow {
		end := start + batchWindow
		if end > len(data) {
			end = len(data)
		}
		n := end - start
		for j := 0; j < n; j++ {
			b, k := f.hashParts(data[start+j])
			prefetchT0(unsafe.Pointer(&f.backing[b]))
			probe[j] = simdBatchProbe{b, k}
		}
		for j := 0; j < n; j++ {
			out[start+j] = f.testAt(probe[j].base, probe[j].key32)
		}
	}
}

// Cap returns the total number of bits.
func (f *SimdFilter) Cap() uint { return uint(f.numBlocks * simdBlockBits) }

// K returns the number of hash positions (fixed at 8, one per lane).
func (f *SimdFilter) K() uint { return simdK }

// Seed returns the hashing seed (0 means unseeded).
func (f *SimdFilter) Seed() uint64 { return f.seed }

// Hash returns the hash function the filter uses.
func (f *SimdFilter) Hash() HashKind { return f.hash }
