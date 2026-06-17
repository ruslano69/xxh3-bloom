package bloom_test

import (
	"testing"

	xxhbloom "github.com/ruslano69/xxh3-bloom"
)

// New blocked filters use fastrange (v6). Verify the full life cycle: no false
// negatives, the on-wire header records v6 + fastrange, and the mode survives a
// serialization round-trip (Equal includes it).
func TestBlockedFastrangeRoundTrip(t *testing.T) {
	const n = 20000
	src := xxhbloom.NewBlocked(n, 0.01)

	keys := make([][]byte, n)
	for i := range keys {
		keys[i] = []byte{byte(i), byte(i >> 8), byte(i >> 16), 0, 0, 0, 0, 0}
		src.Add(keys[i])
	}
	for i, key := range keys {
		if !src.Test(key) {
			t.Fatalf("fastrange false negative at %d", i)
		}
	}

	blob, err := src.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if blob[4] != 6 {
		t.Fatalf("version byte = %d, want 6", blob[4])
	}
	if blob[10] != 1 {
		t.Fatalf("range-mode byte = %d, want 1 (fastrange)", blob[10])
	}

	var dst xxhbloom.BlockedFilter
	if err := dst.UnmarshalBinary(blob); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}
	if !src.Equal(&dst) {
		t.Fatal("round-trip not equal (fastrange flag must survive)")
	}
	for i, key := range keys {
		if !dst.Test(key) {
			t.Fatalf("post-reload false negative at %d", i)
		}
	}
}
