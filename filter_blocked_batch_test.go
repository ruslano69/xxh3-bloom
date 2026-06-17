package bloom

import (
	"encoding/binary"
	"testing"
)

func key8(i int) []byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], uint64(i))
	return b[:]
}

// AddBatch must lay out exactly the same bits as a loop of Add.
func TestAddBatchMatchesAdd(t *testing.T) {
	const n = 30000
	loopF := NewBlocked(n, 0.01)
	batchF := NewBlocked(n, 0.01)

	keys := make([][]byte, n)
	for i := range keys {
		keys[i] = key8(i)
		loopF.Add(keys[i])
	}
	batchF.AddBatch(keys)

	if !loopF.Equal(batchF) {
		t.Fatal("AddBatch produced different bits than Add loop")
	}
}

// TestBatch must return exactly what Test returns for every key, for a mix of
// inserted and absent keys (and a length that is not a multiple of the window).
func TestTestBatchMatchesTest(t *testing.T) {
	const n = 30000
	f := NewBlocked(n, 0.01)
	for i := 0; i < n; i++ {
		f.Add(key8(i))
	}

	const q = 20003 // deliberately not a multiple of batchWindow
	queries := make([][]byte, q)
	for i := range queries {
		if i%2 == 0 {
			queries[i] = key8(i / 2) // present
		} else {
			queries[i] = key8(n + i) // absent
		}
	}

	out := make([]bool, q)
	f.TestBatch(queries, out)

	for i, k := range queries {
		if want := f.Test(k); out[i] != want {
			t.Fatalf("TestBatch[%d]=%v, Test=%v", i, out[i], want)
		}
	}
	// no false negatives on the inserted half
	for i := 0; i < q; i += 2 {
		if !out[i] {
			t.Fatalf("false negative at query %d", i)
		}
	}
}
