//go:build amd64

package bloom

import "unsafe"

// prefetchT0 hints the CPU to load the cache line at addr (PREFETCHT0). It lets
// the batch path keep several memory accesses in flight at once. Implemented in
// prefetch_amd64.s.
//
//go:noescape
func prefetchT0(addr unsafe.Pointer)
