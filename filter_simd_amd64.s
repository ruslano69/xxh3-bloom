//go:build amd64

#include "textflag.h"

// Build the 8-lane mask for key32 into Y5, clobbering Y0..Y4.
//   Y0 = broadcast(key32)
//   Y1 = simdSalt
//   Y2 = key32 * salt           (per 32-bit lane, wrapping)
//   Y3 = Y2 >> 27               (top 5 bits -> 0..31)
//   Y4 = 1 per lane             (all-ones >> 31)
//   Y5 = 1 << Y3                (one bit per lane = mask)
// The key32 argument lives at key32+8(FP) in both callers.
#define MAKE_MASK \
	VPBROADCASTD key32+8(FP), Y0 \
	VMOVDQU      ·simdSalt(SB), Y1 \
	VPMULLD      Y1, Y0, Y2 \
	VPSRLD       $27, Y2, Y3 \
	VPCMPEQD     Y4, Y4, Y4 \
	VPSRLD       $31, Y4, Y4 \
	VPSLLVD      Y3, Y4, Y5

// func simdSetAVX2(block *uint32, key32 uint32)
TEXT ·simdSetAVX2(SB), NOSPLIT, $0-12
	MOVQ block+0(FP), AX
	MAKE_MASK
	VMOVDQU (AX), Y6      // current block
	VPOR    Y5, Y6, Y6    // block |= mask
	VMOVDQU Y6, (AX)
	VZEROUPPER
	RET

// func simdCheckAVX2(block *uint32, key32 uint32) bool
TEXT ·simdCheckAVX2(SB), NOSPLIT, $0-17
	MOVQ block+0(FP), AX
	MAKE_MASK
	VMOVDQU (AX), Y6      // block
	VPANDN  Y5, Y6, Y7    // Y7 = (NOT block) AND mask
	VPTEST  Y7, Y7        // ZF = (Y7 == 0)  i.e. mask subset of block
	SETEQ   ret+16(FP)
	VZEROUPPER
	RET
