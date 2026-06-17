#include "textflag.h"

// func prefetchT0(addr unsafe.Pointer)
// Issues a PREFETCHT0 hint to pull the line at addr into all cache levels.
TEXT ·prefetchT0(SB), NOSPLIT, $0-8
	MOVQ addr+0(FP), AX
	PREFETCHT0 (AX)
	RET
