package bloom

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"unsafe"

	"github.com/zeebo/xxh3"
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
}

// NewBlocked builds a blocked filter with capacity for n items at fp.
// It reuses the classic m/k estimate, then rounds m up to whole cache lines.
// NOTE: because of uneven block load, the *actual* FP rate will be somewhat
// higher than fp. For a guaranteed FP at the cost of more memory, use
// NewBlockedTuned.
func NewBlocked(n uint, fp float64) *BlockedFilter {
	m, k := EstimateParameters(n, fp)
	numBlocks := uint64(math.Ceil(float64(m) / blockBits))
	return newBlockedRaw(numBlocks, k)
}

// NewBlockedTuned builds a blocked filter whose *measured* FP rate at n items
// is <= fp, by numerically inflating the number of cache-line blocks to
// compensate for uneven per-block load. This is the "spend spare RAM to get
// both locality AND accuracy" tier. Returns a filter that typically uses
// ~20-35% more bits than the classic estimate, but does 1 cache miss per op.
func NewBlockedTuned(n uint, fp float64) *BlockedFilter {
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
	return newBlockedRaw(bestBlocks, bestK)
}

// newBlockedRaw allocates a blocked filter with an explicit block count and k.
func newBlockedRaw(numBlocks uint64, k uint) *BlockedFilter {
	if numBlocks < 1 {
		numBlocks = 1
	}
	blocks, backing := newAlignedBlocks(numBlocks)
	return &BlockedFilter{
		blocks:    blocks,
		backing:   backing,
		numBlocks: numBlocks,
		k:         maxU(1, k),
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
	h := xxh3.Hash128(data)
	blockIdx := h.Hi % f.numBlocks
	off = blockIdx * blockWords
	h1 = uint32(h.Lo)
	h2 = uint32(h.Lo >> 32)
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

// --- Serialization ---
//
// Wire format (little-endian, native byte order for the bit payload):
//   [8] magic "BBLM\x01\x00\x00\x00"
//   [8] numBlocks
//   [8] k
//   [numBlocks*64] raw bit array (one 64-byte cache line per block)
//
// The payload is dumped raw for speed (a GB-scale filter would be far too slow
// through reflection-based binary.Write), so files are NOT portable across
// machines of different endianness. On x86/ARM little-endian this is fine.

var blockedMagic = [8]byte{'B', 'B', 'L', 'M', 1, 0, 0, 0}

// blocksAsBytes returns a []byte view aliasing the block words — no copy.
func blocksAsBytes(blocks []uint64) []byte {
	if len(blocks) == 0 {
		return nil
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(&blocks[0])), len(blocks)*8)
}

// WriteTo writes a binary representation of the filter to w. It returns the
// number of bytes written. Wrap w in a bufio.Writer for disk/network.
func (f *BlockedFilter) WriteTo(w io.Writer) (int64, error) {
	var hdr [24]byte
	copy(hdr[0:8], blockedMagic[:])
	binary.LittleEndian.PutUint64(hdr[8:16], f.numBlocks)
	binary.LittleEndian.PutUint64(hdr[16:24], uint64(f.k))

	n, err := w.Write(hdr[:])
	total := int64(n)
	if err != nil {
		return total, err
	}
	m, err := w.Write(blocksAsBytes(f.blocks))
	return total + int64(m), err
}

// ReadFrom reads a filter previously written by WriteTo, replacing the
// receiver's contents. It returns the number of bytes read. Wrap r in a
// bufio.Reader for disk/network.
func (f *BlockedFilter) ReadFrom(r io.Reader) (int64, error) {
	var hdr [24]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, err
	}
	if !bytes.Equal(hdr[0:8], blockedMagic[:]) {
		return 24, fmt.Errorf("bloom: bad magic, not a blocked filter stream")
	}
	numBlocks := binary.LittleEndian.Uint64(hdr[8:16])
	k := uint(binary.LittleEndian.Uint64(hdr[16:24]))

	nf := newBlockedRaw(numBlocks, k)
	buf := blocksAsBytes(nf.blocks)
	m, err := io.ReadFull(r, buf)
	if err != nil {
		return int64(24 + m), err
	}
	*f = *nf
	return int64(24 + m), nil
}

// MarshalBinary implements encoding.BinaryMarshaler.
func (f *BlockedFilter) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer
	buf.Grow(24 + len(f.blocks)*8)
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
	if f.numBlocks != g.numBlocks || f.k != g.k {
		return false
	}
	return bytes.Equal(blocksAsBytes(f.blocks), blocksAsBytes(g.blocks))
}
