/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#ifndef __EXCEPTIONS_CLEANUP_H__
#define __EXCEPTIONS_CLEANUP_H__

/* progs/exceptions_cleanup.c: one bit per frame that reports it ran. */
#define RAN_FOO3_PREEMPT	0x1
#define RAN_FOO2_RCU		0x2
#define RAN_FOO1V_PREEMPT	0x4
#define RAN_FOO2_DROP		0x8
#define RAN_BUMP		0x10

/* progs/exceptions_cleanup_shapes.c: one bit per shape. */
#define RAN_REGS		0x1
#define RAN_WIDE_REC		0x2
#define RAN_RESUME_ALIAS	0x4
#define RAN_NOP_PAD		0x8
#define RAN_VAR_STACK		0x10
#define RAN_GAP_INNER		0x20
#define RAN_GAP_OUTER		0x40
#define RAN_NO_EXIT_JA		0x80
#define RAN_CALLX		0x100
#define RAN_HELD_REF		0x200

#define CLEANUP_REC(begin, end, landing_pad)			\
	".pushsection .bpf_cleanup,\"a\",@progbits;"		\
	".long " begin ";"					\
	".long " end ";"					\
	".long " landing_pad ";"				\
	".popsection;"

/* Set a bit in @pads_ran. */
#define PAD_RAN(bit)						\
	"r1 = %[pads_ran] ll;"					\
	"r2 = *(u64 *)(r1 + 0);"				\
	"r2 |= " bit ";"					\
	"*(u64 *)(r1 + 0) = r2;"

#endif /* __EXCEPTIONS_CLEANUP_H__ */
