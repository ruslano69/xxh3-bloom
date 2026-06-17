//go:build !amd64

package bloom

import "unsafe"

// prefetchT0 is a no-op on architectures without a software-prefetch stub. The
// batch API still works (the two-phase structure alone gives some memory-level
// parallelism via out-of-order execution), just without the explicit hint.
func prefetchT0(addr unsafe.Pointer) { _ = addr }
