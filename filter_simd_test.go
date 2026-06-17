package bloom

import "testing"

// No key that was added may ever read as absent (Bloom's core guarantee).
func TestSimdNoFalseNegatives(t *testing.T) {
	const n = 200000
	f := NewSimd(n, 0.01)
	for i := 0; i < n; i++ {
		f.Add(key8(i))
	}
	for i := 0; i < n; i++ {
		if !f.Test(key8(i)) {
			t.Fatalf("false negative for key %d", i)
		}
	}
}

// The measured FP rate should land near the split-block ballpark for k=8 at
// ~256 bits/block sized for 1%. It is allowed to run a little hot (the
// one-bit-per-lane layout is less accurate than a free k=8), but a blow-up
// would signal a layout bug.
func TestSimdFalsePositiveRate(t *testing.T) {
	const n = 200000
	f := NewSimd(n, 0.01)
	for i := 0; i < n; i++ {
		f.Add(key8(i))
	}
	const trials = 200000
	fp := 0
	for i := 0; i < trials; i++ {
		if f.Test(key8(n + i)) { // keys never inserted
			fp++
		}
	}
	rate := float64(fp) / float64(trials)
	if rate > 0.03 {
		t.Fatalf("FP rate %.4f too high (expected < 3%% for a 1%%-sized split-block)", rate)
	}
	t.Logf("simd FP rate = %.4f over %d trials", rate, trials)
}

// The exported Add/Test (AVX2 on this machine) must lay down byte-for-byte the
// same blocks as the scalar reference, and answer membership identically.
func TestSimdVectorMatchesScalar(t *testing.T) {
	const n = 50000
	vec := NewSimd(n, 0.01)
	ref := NewSimd(n, 0.01)
	for i := 0; i < n; i++ {
		vec.Add(key8(i)) // exported path (AVX2 where available)
		ref.addScalar(key8(i))
	}
	for i := range vec.backing {
		if vec.backing[i] != ref.backing[i] {
			t.Fatalf("backing[%d]: vector=%08x scalar=%08x", i, vec.backing[i], ref.backing[i])
		}
	}
	const q = 100000
	for i := 0; i < q; i++ {
		k := key8(i) // half present, half absent
		if vec.Test(k) != ref.testScalar(k) {
			t.Fatalf("Test disagree at key %d: vector=%v scalar=%v", i, vec.Test(k), ref.testScalar(k))
		}
	}
}

// AddBatch must lay out exactly the same bits as a loop of Add.
func TestSimdAddBatchMatchesAdd(t *testing.T) {
	const n = 30000
	loopF := NewSimd(n, 0.01)
	batchF := NewSimd(n, 0.01)
	keys := make([][]byte, n)
	for i := range keys {
		keys[i] = key8(i)
		loopF.Add(keys[i])
	}
	batchF.AddBatch(keys)
	for i := range loopF.backing {
		if loopF.backing[i] != batchF.backing[i] {
			t.Fatalf("backing[%d]: loop=%08x batch=%08x", i, loopF.backing[i], batchF.backing[i])
		}
	}
}

// TestBatch must return exactly what Test returns for every key (length not a
// multiple of the window, mix of present/absent).
func TestSimdTestBatchMatchesTest(t *testing.T) {
	const n = 30000
	f := NewSimd(n, 0.01)
	for i := 0; i < n; i++ {
		f.Add(key8(i))
	}
	const q = 20003
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
}

// NewSimdTuned's measured FP must land at or under the target, and it must cost
// more memory than the untuned NewSimd (the whole point of the tier).
func TestSimdTunedHitsTarget(t *testing.T) {
	const n = 300000
	for _, fp := range []float64{0.02, 0.01, 0.005} {
		plain := NewSimd(n, fp)
		tuned := NewSimdTuned(n, fp)
		if tuned.Cap() <= plain.Cap() {
			t.Fatalf("fp=%.3f: tuned Cap %d not larger than plain %d", fp, tuned.Cap(), plain.Cap())
		}
		for i := 0; i < n; i++ {
			tuned.Add(key8(i))
		}
		const trials = 500000
		bad := 0
		for i := 0; i < trials; i++ {
			if tuned.Test(key8(n + i)) {
				bad++
			}
		}
		rate := float64(bad) / float64(trials)
		over := tuned.Cap() - plain.Cap()
		t.Logf("fp=%.3f: measured=%.4f  +%.1f%% mem", fp, rate, 100*float64(over)/float64(plain.Cap()))
		if rate > fp {
			t.Fatalf("fp=%.3f: measured %.4f exceeds target", fp, rate)
		}
	}
}

func TestSimdInvariants(t *testing.T) {
	f := NewSimd(1000, 0.01)
	if f.K() != 8 {
		t.Fatalf("K()=%d, want 8", f.K())
	}
	if f.Cap()%simdBlockBits != 0 {
		t.Fatalf("Cap()=%d not a whole number of 256-bit blocks", f.Cap())
	}
}
