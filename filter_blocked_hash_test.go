package bloom

import (
	"fmt"
	"testing"

	"github.com/zeebo/xxh3"
)

// TestAddHashParityWithAdd proves the hashed-input fast path is bit-for-bit
// identical to the []byte path: feeding AddHash the same xxh3-128 the internal
// hasher would compute (seed 0) must set exactly the same bits.
func TestAddHashParityWithAdd(t *testing.T) {
	const n = 5000
	viaBytes := NewBlockedTuned(n, 0.01)
	viaHash := NewBlockedTuned(n, 0.01)

	for i := 0; i < n; i++ {
		key := []byte(fmt.Sprintf("key-%d", i))
		viaBytes.Add(key)
		h := xxh3.Hash128(key) // matches xxh3Hash(key, 0) used by Add
		viaHash.AddHash(h.Hi, h.Lo)
	}

	if !viaBytes.Equal(viaHash) {
		t.Fatal("AddHash produced a different bit layout than Add for the same keys")
	}
}

// TestTestHashAgreesWithTest checks TestHash mirrors Test for both members and
// non-members on a filter built via the []byte path.
func TestTestHashAgreesWithTest(t *testing.T) {
	const n = 4000
	f := NewBlockedTuned(n, 0.01)
	for i := 0; i < n; i++ {
		f.Add([]byte(fmt.Sprintf("present-%d", i)))
	}

	check := func(s string) {
		key := []byte(s)
		h := xxh3.Hash128(key)
		if got, want := f.TestHash(h.Hi, h.Lo), f.Test(key); got != want {
			t.Fatalf("TestHash(%q)=%v but Test=%v", s, got, want)
		}
	}
	for i := 0; i < n; i++ {
		check(fmt.Sprintf("present-%d", i)) // members: both true
		check(fmt.Sprintf("absent-%d", i))  // non-members: both agree
	}
}

// TestAddHashTestHashRoundTrip is the self-consistency a hashed-only caller
// relies on: a key added via AddHash is found via TestHash, and an unrelated key
// is (almost always) not. No []byte path involved.
func TestAddHashTestHashRoundTrip(t *testing.T) {
	const n = 10000
	f := NewBlockedTuned(n, 0.01)
	hashOf := func(i int) (uint64, uint64) {
		h := xxh3.HashString128Seed(fmt.Sprintf("item%d", i), 0xABCD)
		return h.Hi, h.Lo
	}
	for i := 0; i < n; i++ {
		f.AddHash(hashOf(i))
	}
	for i := 0; i < n; i++ {
		if !f.TestHash(hashOf(i)) {
			t.Fatalf("false negative for item%d via hashed path", i)
		}
	}
	// Spot-check FP stays sane on absent keys (seed-shifted so they differ).
	fp := 0
	for i := 0; i < n; i++ {
		h := xxh3.HashString128Seed(fmt.Sprintf("missing%d", i), 0x1234)
		if f.TestHash(h.Hi, h.Lo) {
			fp++
		}
	}
	if rate := float64(fp) / float64(n); rate > 0.03 {
		t.Fatalf("hashed-path FP rate %.4f too high (want <= ~0.01 tuned)", rate)
	}
}
