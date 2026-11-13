/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __TEXT_INSN_H
#define __TEXT_INSN_H

#include <linux/types.h>

/*
 * What one machine instruction does to the integer registers and to the
 * control flow, in terms which do not depend on the arch. It is what a data
 * flow analysis of copies needs, see text_flow.h.
 *
 * A decoder looks at one instruction and keeps no state. It has to get right
 * the length, the kind and the registers which are written. An instruction
 * which it does not know is TEXT_OTHER and writes TEXT_ALL_REGS. It may leave
 * out a value which dst can get, and never names one which dst cannot get:
 * "dst = src or a value which is computed" is a TEXT_SELECT of src and src.
 */
enum text_insn_kind {
	TEXT_OTHER,
	TEXT_MOV_IMM,		/* dst = imm or imm2 */
	TEXT_MOV,		/* dst = src */
	TEXT_SEXT32,		/* dst = (s32)src */
	TEXT_SELECT,		/* dst = src or src2 */
	TEXT_SELECT_IMM,	/* dst = src or imm */
	TEXT_BRANCH,		/* to imm, 0 if it is computed */
	TEXT_COND_BRANCH,	/* to imm or to the next instruction */
	TEXT_CALL,		/* of imm, 0 if it is computed */
	TEXT_RETURN,
};

/* The arch numbers its registers */
#define TEXT_MAX_REGS	32
#define TEXT_ALL_REGS	(~0U)
#define TEXT_NO_INSN	(~0U)

struct text_insn {
	u8 kind;
	u8 len;
	u8 dst, src, src2;
	bool is32;	/* It works on the low 32 bits and zero extends the result */
	/* The registers which it writes, but for dst */
	u32 defs;
	u64 imm, imm2;
	/* For the user of the decoder */
	u64 addr;
	u32 target;	/* the index of the instruction at imm */
};

struct text_arch {
	u8 retval;		/* the register with the return value */
	u32 caller_saved;	/* the registers which a call may write */
	/* A branch to this symbol is a return */
	const char *return_thunk;
	/*
	 * Describe the instruction at ADDR, whose bytes are at CODE. At most LEN
	 * bytes can be read. Return a negative value if it is not an instruction.
	 */
	int (*decode)(const void *code, unsigned int len, u64 addr, struct text_insn *insn);
};

#ifdef HAVE_LLVM_MC
/* Return the arch of the ELF machine MACHINE, or NULL, after a message, if it cannot be decoded */
const struct text_arch *text_arch_init(unsigned int machine);
#else
static inline const struct text_arch *text_arch_init(unsigned int machine)
{
	return NULL;
}
#endif

#endif
