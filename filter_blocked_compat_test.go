package bloom

import (
	"bytes"
	"testing"
)

// Backward compatibility: filters built before v6 selected the block with a
// modulo. This test builds a modulo filter directly (the path new constructors
// no longer take), exercises Add/Test on it, and confirms a v5-versioned stream
// loads back as modulo with no false negatives — proving old files still work.
func TestBlockedModuloCompat(t *testing.T) {
	const n = 5000
	m, k := EstimateParameters(n, 0.01)
	numBlocks := (uint64(m) + blockBits - 1) / blockBits
	h, err := resolveHasher(XXH3)
	if err != nil {
		t.Fatalf("resolveHasher: %v", err)
	}
	f := allocBlocked(numBlocks, k, 0, XXH3, h, false) // modulo, like a v5 filter
	if f.fastrange {
		t.Fatal("expected a modulo filter")
	}

	keys := make([][]byte, n)
	for i := range keys {
		keys[i] = []byte{byte(i), byte(i >> 8), byte(i >> 16), 0, 0, 0, 0, 0}
		f.Add(keys[i])
	}
	for i, key := range keys {
		if !f.Test(key) {
			t.Fatalf("modulo false negative at %d", i)
		}
	}

	// WriteTo emits v6 with rangeMode=0 (modulo). Patch the version byte to 5 to
	// emulate a genuine pre-v6 file; the payload is a real modulo layout, so a
	// correct reader must reload it as modulo and find every key.
	var buf bytes.Buffer
	if _, err := f.WriteTo(&buf); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	raw := buf.Bytes()
	if raw[10] != rangeModeModulo {
		t.Fatalf("range-mode byte = %d, want modulo(0)", raw[10])
	}
	raw[4] = 5 // pretend this is a v5 file

	var g BlockedFilter
	if _, err := g.ReadFrom(bytes.NewReader(raw)); err != nil {
		t.Fatalf("ReadFrom v5: %v", err)
	}
	if g.fastrange {
		t.Fatal("a v5 file must load as modulo")
	}
	for i, key := range keys {
		if !g.Test(key) {
			t.Fatalf("v5 reload false negative at %d", i)
		}
	}
}
