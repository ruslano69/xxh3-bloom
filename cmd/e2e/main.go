package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"time"

	xxhbloom "github.com/ruslano69/xxh3-bloom"
	murbloom "github.com/bits-and-blooms/bloom/v3"
)

func main() {
	capacity := flag.Uint64("capacity", 2_000_000_000, "filter capacity (n elements)")
	fillPct := flag.Float64("fill", 50.0, "fill percentage 0-100")
	fpRate := flag.Float64("fp", 0.01, "target false positive rate")
	queries := flag.Uint64("queries", 10_000_000, "number of query-phase ops")
	compare := flag.Bool("compare", false, "also run Murmur3 for comparison")
	blocked := flag.Bool("blocked", false, "also run Blocked (cache-line) filter")
	tuned := flag.Bool("tuned", false, "also run Blocked-Tuned (more RAM, FP-accurate) filter")
	flag.Parse()

	fillN := uint64(float64(*capacity) * *fillPct / 100.0)

	fmt.Println("=== E2E Bloom Filter Benchmark ===")
	fmt.Printf("Capacity : %s elements\n", commas(*capacity))
	fmt.Printf("FP target: %.2f%%\n", *fpRate*100)
	fmt.Printf("Fill     : %.1f%% = %s elements\n", *fillPct, commas(fillN))
	fmt.Println()

	runBench("XXH3", fillN, *capacity, *fpRate, *queries, newXXH3, addXXH3, testXXH3)

	if *compare {
		fmt.Println()
		runBench("Murmur3", fillN, *capacity, *fpRate, *queries, newMur, addMur, testMur)
	}

	if *blocked {
		fmt.Println()
		runBench("Blocked-XXH3", fillN, *capacity, *fpRate, *queries, newBlocked, addXXH3, testXXH3)
	}

	if *tuned {
		fmt.Println()
		runBench("Blocked-Tuned", fillN, *capacity, *fpRate, *queries, newTuned, addXXH3, testXXH3)
	}
}

// --- generic runner ---

type filterAdd func(key []byte)
type filterTest func(key []byte) bool
type filterNew func(capacity uint64, fp float64) (filterAdd, filterTest, uint, uint)

func runBench(name string, fillN, capacity uint64, fp float64, queries uint64,
	newFn filterNew, add filterAdd, test filterTest) {

	// newFn recreates fresh filter and rebinds add/test
	add, test, m, k := newFn(capacity, fp)

	fmt.Printf("--- %s ---\n", name)
	fmt.Printf("Bits (m) : %s  (%.2f GB)\n", commas(uint64(m)), float64(m)/8/1e9)
	fmt.Printf("Hash fns : %d\n", k)
	fmt.Println()

	// ---- Fill phase ----
	fmt.Println("[Fill phase]")
	buf := make([]byte, 8)
	progress := fillN / 100
	if progress == 0 {
		progress = 1
	}

	start := time.Now()
	for i := uint64(0); i < fillN; i++ {
		binary.LittleEndian.PutUint64(buf, i)
		add(buf)

		if (i+1)%progress == 0 {
			pct := float64(i+1) / float64(fillN)
			elapsed := time.Since(start)
			eta := time.Duration(float64(elapsed)/pct) - elapsed
			opsec := float64(i+1) / elapsed.Seconds()
			fmt.Printf("\r  %s / %s  %3.0f%%   elapsed: %s   ETA: %s   %.1fM ops/sec   ",
				commas(i+1), commas(fillN), pct*100,
				fmtDur(elapsed), fmtDur(eta), opsec/1e6)
		}
	}
	fillDur := time.Since(start)
	nsPerOp := float64(fillDur.Nanoseconds()) / float64(fillN)
	fmt.Printf("\r  Done: %s ops in %s = %.0f ns/op = %.2fM ops/sec%30s\n",
		commas(fillN), fmtDur(fillDur), nsPerOp, 1e9/nsPerOp/1e6, "")

	// ---- Query: true positives ----
	fmt.Println("\n[Query phase — true positives (inserted keys)]")
	start = time.Now()
	for i := uint64(0); i < queries; i++ {
		binary.LittleEndian.PutUint64(buf, i%fillN)
		test(buf)
	}
	tpDur := time.Since(start)
	fmt.Printf("  %s queries in %s = %.0f ns/op = %.2fM ops/sec\n",
		commas(queries), fmtDur(tpDur),
		float64(tpDur.Nanoseconds())/float64(queries),
		float64(queries)/tpDur.Seconds()/1e6)

	// ---- Query: true negatives / FP measurement ----
	fmt.Println("\n[Query phase — true negatives (non-inserted keys)]")
	fp_count := uint64(0)
	start = time.Now()
	for i := uint64(0); i < queries; i++ {
		binary.LittleEndian.PutUint64(buf, capacity+i+1) // keys above capacity → not inserted
		if test(buf) {
			fp_count++
		}
	}
	tnDur := time.Since(start)
	fpActual := float64(fp_count) / float64(queries) * 100
	fmt.Printf("  %s queries in %s = %.0f ns/op = %.2fM ops/sec\n",
		commas(queries), fmtDur(tnDur),
		float64(tnDur.Nanoseconds())/float64(queries),
		float64(queries)/tnDur.Seconds()/1e6)
	fmt.Printf("  False positives: %s / %s = %.4f%% (target %.2f%%)\n\n",
		commas(fp_count), commas(queries), fpActual, fp*100)
}

// --- filter adapters ---

func newXXH3(capacity uint64, fp float64) (filterAdd, filterTest, uint, uint) {
	f := xxhbloom.NewWithEstimates(uint(capacity), fp)
	return func(key []byte) { f.Add(key) },
		func(key []byte) bool { return f.Test(key) },
		f.Cap(), f.K()
}

func addXXH3(_ []byte)       {}
func testXXH3(_ []byte) bool { return false }

func newMur(capacity uint64, fp float64) (filterAdd, filterTest, uint, uint) {
	f := murbloom.NewWithEstimates(uint(capacity), fp)
	return func(key []byte) { f.Add(key) },
		func(key []byte) bool { return f.Test(key) },
		f.Cap(), f.K()
}

func addMur(_ []byte)       {}
func testMur(_ []byte) bool { return false }

func newBlocked(capacity uint64, fp float64) (filterAdd, filterTest, uint, uint) {
	f := xxhbloom.NewBlocked(uint(capacity), fp)
	return func(key []byte) { f.Add(key) },
		func(key []byte) bool { return f.Test(key) },
		f.Cap(), f.K()
}

func newTuned(capacity uint64, fp float64) (filterAdd, filterTest, uint, uint) {
	f := xxhbloom.NewBlockedTuned(uint(capacity), fp)
	return func(key []byte) { f.Add(key) },
		func(key []byte) bool { return f.Test(key) },
		f.Cap(), f.K()
}

// --- helpers ---

func commas(n uint64) string {
	s := fmt.Sprintf("%d", n)
	out := make([]byte, 0, len(s)+(len(s)-1)/3)
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, byte(c))
	}
	return string(out)
}

func fmtDur(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second
	if h > 0 {
		return fmt.Sprintf("%dh%02dm%02ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm%02ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}
