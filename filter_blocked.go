package bloom

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"math/bits"
	"unsafe"
)

// A Blocked Bloom Filter confines all k bits of a key to a single CPU cache
// line (64 bytes = 512 bits). One hash picks the block; the remaining bits
// derive the k positions *inside* that block. Result: exactly ONE memory
// access (one cache miss) per Add/Test, instead of k scattered accesses.
//
// Tradeoff: because keys are not spread uniformly across the whole bit array
// (each key is locked into one block), block load is uneven and the
// false-positive rate is slightly worse than a classic filter for the same
// m/k. In practice you spend ~25% more bits to match FP — cheap next to the
// throughput gain at scale.

const (
	blockBits  = 512               // one cache line worth of bits (64 B)
	blockWords = blockBits / 64     // 8 uint64 per block
	blockMask  = blockBits - 1      // for & instead of % (512 is power of two)
)

type BlockedFilter struct {
	blocks    []uint64 // 64-byte aligned view, len = numBlocks*blockWords
	backing   []uint64 // real allocation (alignment slack)
	numBlocks uint64
	k         uint
	seed      uint64 // keyed-hash seed; 0 = unseeded (see RandomSeed / threat model)
	hash      HashKind
	hasher    Hasher
}

// NewBlocked builds a blocked filter with capacity for n items at fp, configured
// by opts. It reuses the classic m/k estimate, then rounds m up to whole cache
// lines. NOTE: because of uneven block load, the *actual* FP rate will be
// somewhat higher than fp. For a guaranteed FP at the cost of more memory, use
// NewBlockedTuned.
func NewBlocked(n uint, fp float64, opts ...Option) *BlockedFilter {
	c := buildConfig(opts)
	m, k := EstimateParameters(n, fp)
	numBlocks := uint64(math.Ceil(float64(m) / blockBits))
	return newBlockedRaw(numBlocks, k, c)
}

// NewBlockedTuned builds a blocked filter whose *measured* FP rate at n items
// is <= fp, by numerically inflating the number of cache-line blocks to
// compensate for uneven per-block load. This is the "spend spare RAM to get
// both locality AND accuracy" tier. Returns a filter that typically uses
// ~20-35% more bits than the classic estimate, but does 1 cache miss per op.
func NewBlockedTuned(n uint, fp float64, opts ...Option) *BlockedFilter {
	c := buildConfig(opts)
	if n == 0 {
		n = 1
	}
	// EstimateBlockedFP is a model with a small optimistic bias (it assumes the
	// k probe bits are independent; double-hashing inside a 512-bit block
	// collides a bit more than that). Tune against a stricter internal target
	// so the *measured* rate lands at or under fp.
	const safety = 0.75
	internal := fp * safety

	bestBlocks := uint64(0)
	bestK := uint(1)
	bestBits := uint64(math.MaxUint64)
	// Search k; for each k, find the fewest blocks meeting the target FP,
	// then keep the (k, blocks) pair using the least total memory.
	for k := uint(1); k <= 20; k++ {
		nb := minBlocksForK(n, internal, k)
		if bits := nb * blockBits; bits < bestBits {
			bestBits, bestBlocks, bestK = bits, nb, k
		}
	}
	return newBlockedRaw(bestBlocks, bestK, c)
}

// NewBlockedWithSeed is shorthand for NewBlocked(n, fp, WithSeed(seed)).
//
// Deprecated: use NewBlocked(n, fp, WithSeed(seed)).
func NewBlockedWithSeed(n uint, fp float64, seed uint64) *BlockedFilter {
	return NewBlocked(n, fp, WithSeed(seed))
}

// NewBlockedTunedWithSeed is shorthand for NewBlockedTuned(n, fp, WithSeed(seed)).
//
// Deprecated: use NewBlockedTuned(n, fp, WithSeed(seed)).
func NewBlockedTunedWithSeed(n uint, fp float64, seed uint64) *BlockedFilter {
	return NewBlockedTuned(n, fp, WithSeed(seed))
}

// newBlockedRaw resolves the hasher (panicking on an unknown hash — a
// construction-time programmer error) and allocates the filter.
func newBlockedRaw(numBlocks uint64, k uint, c config) *BlockedFilter {
	h, err := resolveHasher(c.hash)
	if err != nil {
		panic(err)
	}
	return allocBlocked(numBlocks, k, c.seed, c.hash, h)
}

// allocBlocked builds the struct from already-resolved parts (shared by
// construction and deserialization, which resolves the hasher itself).
func allocBlocked(numBlocks uint64, k uint, seed uint64, hash HashKind, hasher Hasher) *BlockedFilter {
	if numBlocks < 1 {
		numBlocks = 1
	}
	blocks, backing := newAlignedBlocks(numBlocks)
	return &BlockedFilter{
		blocks:    blocks,
		backing:   backing,
		numBlocks: numBlocks,
		k:         maxU(1, k),
		seed:      seed,
		hash:      hash,
		hasher:    hasher,
	}
}

// minBlocksForK returns the smallest block count whose estimated blocked FP
// rate at n items is <= fp, for a fixed k. FP decreases monotonically as
// blocks grow (lower per-block load), so we binary-search.
func minBlocksForK(n uint, fp float64, k uint) uint64 {
	fpAt := func(nb uint64) float64 {
		return EstimateBlockedFP(n, nb, k)
	}
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

// EstimateBlockedFP estimates the false-positive rate of a blocked filter with
// numBlocks cache lines and k hashes, holding n items. Keys land in blocks
// following a Poisson distribution with mean lambda = n/numBlocks; within a
// block of B bits holding j keys the FP is (1 - e^(-k*j/B))^k. We average that
// over the Poisson load. (Putze, Sanders, Singler, 2007.)
func EstimateBlockedFP(n uint, numBlocks uint64, k uint) float64 {
	if numBlocks < 1 {
		numBlocks = 1
	}
	lambda := float64(n) / float64(numBlocks)
	// Hopelessly overloaded block => every bit set => FP ~ 1. Short-circuit
	// (also keeps the summation range below bounded).
	if lambda > 1000 {
		return 1.0
	}
	const B = blockBits
	kf := float64(k)
	hi := int(lambda + 10*math.Sqrt(lambda) + 10)

	sum := 0.0
	logLambda := math.Log(lambda)
	logPmf := -lambda // log P(j=0) = -lambda
	for j := 0; j <= hi; j++ {
		if j > 0 {
			logPmf += logLambda - math.Log(float64(j))
		}
		pmf := math.Exp(logPmf)
		inner := math.Pow(1-math.Exp(-kf*float64(j)/B), kf)
		sum += pmf * inner
	}
	return sum
}

// newAlignedBlocks allocates numBlocks*blockWords uint64 aligned to 64 bytes,
// so each block sits on its own cache line.
func newAlignedBlocks(numBlocks uint64) (view, backing []uint64) {
	n := numBlocks * blockWords
	backing = make([]uint64, n+blockWords) // 64 B of slack for alignment
	addr := uintptr(unsafe.Pointer(&backing[0]))
	// uint64 offset needed to reach the next 64-byte boundary
	off := ((64 - (addr & 63)) & 63) / 8
	view = backing[off : off+uintptr(n)]
	return
}

// blockOffset returns the index in f.blocks where the key's cache line starts,
// plus the two 32-bit sub-hashes used to derive the k bit positions.
func (f *BlockedFilter) blockOffset(data []byte) (off uint64, h1, h2 uint32) {
	hi, lo := f.hasher(data, f.seed)
	blockIdx := hi % f.numBlocks
	off = blockIdx * blockWords
	h1 = uint32(lo)
	h2 = uint32(lo >> 32)
	return
}

// Add inserts data. Touches exactly one cache line.
func (f *BlockedFilter) Add(data []byte) *BlockedFilter {
	off, h1, h2 := f.blockOffset(data)
	for i := uint(0); i < f.k; i++ {
		bit := (h1 + uint32(i)*h2) & blockMask
		f.blocks[off+uint64(bit>>6)] |= 1 << (bit & 63)
	}
	return f
}

// Test reports possible membership. Touches exactly one cache line.
func (f *BlockedFilter) Test(data []byte) bool {
	off, h1, h2 := f.blockOffset(data)
	for i := uint(0); i < f.k; i++ {
		bit := (h1 + uint32(i)*h2) & blockMask
		if f.blocks[off+uint64(bit>>6)]&(1<<(bit&63)) == 0 {
			return false
		}
	}
	return true
}

// Cap returns the total number of bits.
func (f *BlockedFilter) Cap() uint { return uint(f.numBlocks * blockBits) }

// K returns the number of hash functions.
func (f *BlockedFilter) K() uint { return f.k }

// Seed returns the hashing seed (0 means unseeded).
func (f *BlockedFilter) Seed() uint64 { return f.seed }

// Hash returns the hash function the filter uses.
func (f *BlockedFilter) Hash() HashKind { return f.hash }

// --- Serialization ---
//
// The wire format is self-describing. v3 and v4 share a 40-byte header:
//   [8] magic   "BBLM\x0v\x00\x00\x00"   (byte 4 = format version)
//   [1] payload endianness   0 = little, 1 = big
//   [1] hash kind            (v4 only; v3 implies XXH3)
//   [6] reserved (zero)
//   [8] numBlocks   (little-endian)
//   [8] k           (little-endian)
//   [8] seed        (little-endian)
//   [numBlocks*64] raw bit array, one 64-byte cache line per block
//
// WriteTo bumps the version only when a field actually matters: an XXH3 filter
// is written as v3 (still readable by older v0.3.0 code); a non-XXH3 filter is
// written as v4 so older readers safely refuse it rather than mis-hashing.
//
// The payload is dumped raw for speed. WriteTo emits the host's byte order and
// records it; ReadFrom byte-swaps on the rare cross-endian load, so v3/v4 files
// are portable — unlike v1/v2.
//
// ReadFrom reads every historical format:
//   v1 (24-byte header): magic, numBlocks, k                 — seed 0, XXH3, LE
//   v2 (32-byte header): + seed                              — XXH3, LE
//   v3 (40-byte header): + endianness                        — XXH3
//   v4 (40-byte header): + hash kind
// Use cmd/convert to upgrade old files.

const (
	blockedHdrV1 = 24
	blockedHdrV2 = 32
	blockedHdrV3 = 40
	blockedHdrV4 = 40
)

var blockedMagicPrefix = [4]byte{'B', 'B', 'L', 'M'}

// nativeBigEndian is true on big-endian hosts.
var nativeBigEndian = func() bool {
	x := uint16(1)
	return (*[2]byte)(unsafe.Pointer(&x))[0] == 0
}()

// blocksAsBytes returns a []byte view aliasing the block words — no copy.
func blocksAsBytes(blocks []uint64) []byte {
	if len(blocks) == 0 {
		return nil
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(&blocks[0])), len(blocks)*8)
}

// WriteTo writes the filter to w (v3 for XXH3, v4 otherwise). It returns the
// number of bytes written. Wrap w in a bufio.Writer for disk/network.
func (f *BlockedFilter) WriteTo(w io.Writer) (int64, error) {
	var hdr [blockedHdrV4]byte
	copy(hdr[0:4], blockedMagicPrefix[:])
	if f.hash == XXH3 {
		hdr[4] = 3 // back-compatible with v0.3.0 readers
	} else {
		hdr[4] = 4
		hdr[9] = byte(f.hash)
	}
	if nativeBigEndian {
		hdr[8] = 1
	}
	binary.LittleEndian.PutUint64(hdr[16:24], f.numBlocks)
	binary.LittleEndian.PutUint64(hdr[24:32], uint64(f.k))
	binary.LittleEndian.PutUint64(hdr[32:40], f.seed)

	n, err := w.Write(hdr[:])
	total := int64(n)
	if err != nil {
		return total, err
	}
	m, err := w.Write(blocksAsBytes(f.blocks))
	return total + int64(m), err
}

// ReadFrom reads any version (v1/v2/v3) written by this library, replacing the
// receiver's contents. It returns the number of bytes read. Wrap r in a
// bufio.Reader for disk/network.
func (f *BlockedFilter) ReadFrom(r io.Reader) (int64, error) {
	var magic [8]byte
	if _, err := io.ReadFull(r, magic[:]); err != nil {
		return 0, err
	}
	if !bytes.Equal(magic[0:4], blockedMagicPrefix[:]) {
		return 8, fmt.Errorf("bloom: bad magic, not a blocked filter stream")
	}
	version := magic[4]

	var restSize int
	switch version {
	case 1:
		restSize = blockedHdrV1 - 8
	case 2:
		restSize = blockedHdrV2 - 8
	case 3:
		restSize = blockedHdrV3 - 8
	case 4:
		restSize = blockedHdrV4 - 8
	default:
		return 8, fmt.Errorf("bloom: unsupported blocked format version %d", version)
	}

	rest := make([]byte, restSize)
	if _, err := io.ReadFull(r, rest); err != nil {
		return 8, err
	}

	var numBlocks, seed uint64
	var k uint
	payloadBig := false
	hash := XXH3 // implicit for v1/v2/v3
	switch version {
	case 1:
		numBlocks = binary.LittleEndian.Uint64(rest[0:8])
		k = uint(binary.LittleEndian.Uint64(rest[8:16]))
	case 2:
		numBlocks = binary.LittleEndian.Uint64(rest[0:8])
		k = uint(binary.LittleEndian.Uint64(rest[8:16]))
		seed = binary.LittleEndian.Uint64(rest[16:24])
	case 3, 4:
		payloadBig = rest[0] == 1
		if version == 4 {
			hash = HashKind(rest[1])
		}
		numBlocks = binary.LittleEndian.Uint64(rest[8:16])
		k = uint(binary.LittleEndian.Uint64(rest[16:24]))
		seed = binary.LittleEndian.Uint64(rest[24:32])
	}

	hasher, err := resolveHasher(hash)
	if err != nil {
		return int64(8 + restSize), err
	}

	nf := allocBlocked(numBlocks, k, seed, hash, hasher)
	buf := blocksAsBytes(nf.blocks)
	m, rerr := io.ReadFull(r, buf)
	read := int64(8 + restSize + m)
	if rerr != nil {
		return read, rerr
	}
	if payloadBig != nativeBigEndian {
		swapWords(nf.blocks)
	}
	*f = *nf
	return read, nil
}

// swapWords byte-reverses each 64-bit word in place (cross-endian load path).
func swapWords(words []uint64) {
	for i := range words {
		words[i] = bits.ReverseBytes64(words[i])
	}
}

// MarshalBinary implements encoding.BinaryMarshaler.
func (f *BlockedFilter) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer
	buf.Grow(blockedHdrV4 + len(f.blocks)*8)
	if _, err := f.WriteTo(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (f *BlockedFilter) UnmarshalBinary(data []byte) error {
	_, err := f.ReadFrom(bytes.NewReader(data))
	return err
}

// Equal reports whether two blocked filters have identical shape and contents.
func (f *BlockedFilter) Equal(g *BlockedFilter) bool {
	if f.numBlocks != g.numBlocks || f.k != g.k || f.seed != g.seed || f.hash != g.hash {
		return false
	}
	return bytes.Equal(blocksAsBytes(f.blocks), blocksAsBytes(g.blocks))
}
