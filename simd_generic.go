//go:build !amd64

package bloom

// On non-amd64 there is no AVX2 path; setAt/testAt are the scalar reference.

func (f *SimdFilter) setAt(base uint64, key32 uint32) { f.setScalarAt(base, key32) }

func (f *SimdFilter) testAt(base uint64, key32 uint32) bool { return f.testScalarAt(base, key32) }
