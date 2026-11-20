/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __TEXT_FLOW_H
#define __TEXT_FLOW_H

#include "text_insn.h"

/*
 * Which values does a function return? A backward may data flow analysis of
 * the machine code of one function.
 *
 * The fact at a point of the code is the set of registers whose value at that
 * point may become the return value: the return value register at a return,
 * and before "dst = src" the register src if dst is in the set behind it. The
 * join is the union. Branches are not evaluated, calls write what the ABI lets
 * them write, memory is not tracked.
 *
 * A copy may convert the value, and only the last conversion counts. So there
 * are three sets.
 */
struct text_facts {
	u32 same;	/* returned as it is */
	u32 zext;	/* the low 32 bits are returned, zero extended */
	u32 sext;	/* the low 32 bits are returned, sign extended */
};

/*
 * What has the function done to the objects of its caller when it returns a
 * value? An effect is a call which hands a pointer that is based on a pointer
 * argument to a callee which changes the object, see text_insn.pointers. The
 * sets above stop at an effect: they are about the paths without one. A forward
 * may data flow analysis finds the effects, and the paths from the entry.
 */
enum text_path {
	TEXT_NO_PATH,		/* None shows in the code, see text_flow.insns */
	TEXT_EFFECT_PATH,	/* Each path has an effect */
	TEXT_CLEAN_PATH,
};

/* The facts before an instruction. The join is the union, and the better path */
struct text_reach {
	/*
	 * The registers which may hold a pointer that is based on a pointer argument:
	 * it is computed from the argument without a load, so it points into the
	 * same object. Memory is not tracked: a pointer which is spilled is lost.
	 */
	u32 based;
	u32 path;	/* from the entry to here */
};

struct text_flow {
	const struct text_arch *arch;
	u64 entry;	/* The address of the first instruction which runs ... */
	u32 args;	/* ... and the registers which hold pointer arguments there */
	/*
	 * All instructions of the function in the order of their addresses,
	 * whether they can be reached or not: the way to a block may be a jump
	 * which is patched in at run time, or an exception.
	 */
	struct text_insn *insns;
	u32 nr_insns;
	/* The result: the facts before each instruction */
	struct text_facts *facts;
	struct text_reach *reach;
};

/*
 * Fold constants: "dst = imm or imm2" and a later "dst = src op imm" in the same
 * straight line of code give "dst = imm' or imm2'". Compilers select one of two
 * constants without a branch in this way.
 */
void text_flow_fold(struct text_flow *flow);
/* Compute the facts */
void text_flow_solve(struct text_flow *flow);
/* Return the facts behind instruction I, which is not a branch */
struct text_facts text_flow_out(const struct text_flow *flow, u32 i);

#endif
