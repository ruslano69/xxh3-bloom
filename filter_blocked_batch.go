package bloom

import "unsafe"

// batchWindow is how many keys are hashed-and-prefetched before the probe pass.
// ~16 keeps enough cache-line misses in flight to overlap memory latency
// (memory-level parallelism) without the prefetched lines being evicted before
// they are used. This matches the sweet spot measured in the Rust bench.
const batchWindow = 16

// batchProbe holds the per-key state computed in the prefetch pass so the probe
// pass does not have to re-hash.
type batchProbe struct {
	off  uint64
	a, b uint32
}

// TestBatch reports possible membership for each key in data, writing the answer
// for data[i] to out[i]. out must have len >= len(data).
//
// For large batches it is faster than calling Test in a loop: it processes keys
// in windows, first hashing every key in the window and software-prefetching its
// cache line, then running the k-probe checks. Because the prefetches are issued
// before the dependent loads, several cache misses are in flight at once
// (memory-level parallelism) instead of one strictly serial miss per lookup —
// the win grows once the filter spills out of cache.
func (f *BlockedFilter) TestBatch(data [][]byte, out []bool) {
	var probe [batchWindow]batchProbe
	for base := 0; base < len(data); base += batchWindow {
		end := base + batchWindow
		if end > len(data) {
			end = len(data)
		}
		n := end - base
		// phase 1: hash + prefetch each key's cache line
		for j := 0; j < n; j++ {
			off, a, b := f.blockOffset(data[base+j])
			prefetchT0(unsafe.Pointer(&f.blocks[off]))
			probe[j] = batchProbe{off, a, b}
		}
		// phase 2: probe (lines now in or arriving to cache)
		for j := 0; j < n; j++ {
			off, a, b := probe[j].off, probe[j].a, probe[j].b
			hit := true
			for i := uint(0); i < f.k; i++ {
				bit := a & blockMask
				if f.blocks[off+uint64(bit>>6)]&(1<<(bit&63)) == 0 {
					hit = false
					break
				}
				a += b
				b += uint32(i)
			}
			out[base+j] = hit
		}
	}
}

// AddBatch inserts every key in data. Like TestBatch it hashes and prefetches a
// window of keys before touching their cache lines, keeping several misses in
// flight to speed up the (memory-bound) fill path.
func (f *BlockedFilter) AddBatch(data [][]byte) {
	var probe [batchWindow]batchProbe
	for base := 0; base < len(data); base += batchWindow {
		end := base + batchWindow
		if end > len(data) {
			end = len(data)
		}
		n := end - base
		for j := 0; j < n; j++ {
			off, a, b := f.blockOffset(data[base+j])
			prefetchT0(unsafe.Pointer(&f.blocks[off]))
			probe[j] = batchProbe{off, a, b}
		}
		for j := 0; j < n; j++ {
			off, a, b := probe[j].off, probe[j].a, probe[j].b
			for i := uint(0); i < f.k; i++ {
				bit := a & blockMask
				f.blocks[off+uint64(bit>>6)] |= 1 << (bit & 63)
				a += b
				b += uint32(i)
			}
		}
	}
}
