package bloom

import (
	"fmt"

	"github.com/twmb/murmur3"
	"github.com/zeebo/xxh3"
)

// HashKind identifies the hash function a filter uses. It is stored in the
// serialized form so a filter always reloads with the hash it was built with.
//
// Built-ins occupy 1..127; values >= 128 are reserved for custom hashes
// registered via RegisterHash.
type HashKind uint8

const (
	// XXH3 is the default: fast, alloc-free, 128-bit. Not DoS-resistant unless
	// keyed with a secret seed (see WithSeed / RandomSeed).
	XXH3 HashKind = 1
	// Murmur3 is MurmurHash3-128. Selecting it makes the hashing match the
	// scheme used by github.com/bits-and-blooms/bloom. NOTE: matching the hash
	// is necessary but not sufficient for bit-level interop with another
	// library — the location formula and bit layout must match too.
	Murmur3 HashKind = 2

	customHashFloor HashKind = 128
)

// Hasher returns a 128-bit hash (hi, lo) of data, keyed by seed.
type Hasher func(data []byte, seed uint64) (hi, lo uint64)

var hashRegistry = map[HashKind]Hasher{
	XXH3:    xxh3Hash,
	Murmur3: murmur3Hash,
}

func xxh3Hash(data []byte, seed uint64) (uint64, uint64) {
	h := xxh3.Hash128Seed(data, seed)
	return h.Hi, h.Lo
}

func murmur3Hash(data []byte, seed uint64) (uint64, uint64) {
	return murmur3.SeedSum128(seed, seed, data)
}

// RegisterHash registers a custom Hasher under kind (which must be >= 128).
// To reload a filter serialized with a custom hash, register the same kind with
// a compatible Hasher before calling ReadFrom. Not safe for concurrent use with
// filter construction.
func RegisterHash(kind HashKind, h Hasher) {
	if kind < customHashFloor {
		panic("bloom: custom hash kind must be >= 128")
	}
	if h == nil {
		panic("bloom: nil Hasher")
	}
	hashRegistry[kind] = h
}

func resolveHasher(kind HashKind) (Hasher, error) {
	h, ok := hashRegistry[kind]
	if !ok {
		return nil, fmt.Errorf("bloom: unknown hash kind %d (register it before loading)", kind)
	}
	return h, nil
}

// String renders a HashKind for diagnostics.
func (h HashKind) String() string {
	switch h {
	case XXH3:
		return "XXH3"
	case Murmur3:
		return "Murmur3"
	default:
		return fmt.Sprintf("HashKind(%d)", uint8(h))
	}
}
