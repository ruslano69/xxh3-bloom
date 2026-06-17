//go:build amd64

package bloom

import "golang.org/x/sys/cpu"

// simdHasAVX2 gates the vectorized path. On an amd64 CPU without AVX2 (rare, but
// possible) we fall back to the scalar reference, which lays out identical bits.
var simdHasAVX2 = cpu.X86.HasAVX2

// simdSetAVX2 ORs key32's 8-lane mask into the 256-bit block at block (which
// must point at 8 contiguous uint32). Implemented in simd_amd64.s.
//
//go:noescape
func simdSetAVX2(block *uint32, key32 uint32)

// simdCheckAVX2 reports whether every lane bit of key32's mask is set in the
// 256-bit block at block. Implemented in simd_amd64.s.
//
//go:noescape
func simdCheckAVX2(block *uint32, key32 uint32) bool

// setAt / testAt apply a located (block, key): AVX2 when present (one load +
// OR/store, or load + VPANDN + VPTEST), else the scalar reference.
func (f *SimdFilter) setAt(base uint64, key32 uint32) {
	if !simdHasAVX2 {
		f.setScalarAt(base, key32)
		return
	}
	simdSetAVX2(&f.backing[base], key32)
}

func (f *SimdFilter) testAt(base uint64, key32 uint32) bool {
	if !simdHasAVX2 {
		return f.testScalarAt(base, key32)
	}
	return simdCheckAVX2(&f.backing[base], key32)
}
