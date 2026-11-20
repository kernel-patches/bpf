/* SPDX-License-Identifier: GPL-2.0-only */
/* What precision.c and failing_path.c share */
#ifndef __BPF_PRECISION_H
#define __BPF_PRECISION_H

#include <linux/bpf_verifier.h>

/*
 * The xregs of a mask, see MAX_BPF_XREG. r10 is the same in all states.
 * Its bit stands for the arguments on the stack.
 */
#define XREG_STACK_ARGS	BPF_REG_FP
#define XREG_REGS	GENMASK(BPF_REG_9, BPF_REG_0)
#define XREG_WORDS	BITS_TO_LONGS(MAX_BPF_XREG)

/* What a pass finds about its errors */
struct precision_per_pass {
	/* bitmaps of insns */
	unsigned long *unproven_insns;
	unsigned long *call_insns;		/* lead to unproven insns, or write what is held */
	unsigned long *bad_read_insns;		/* unproven because of an unreadable xreg */
	unsigned long *unproven_funcs;		/* of functions */
	u64 suspect_loops, first_suspect_loops;	/* of the unproven states, of the first one */
	bool disjoint_joined;			/* disjoint values in data_deps were joined */
	bool over_budget, calls_joined;
	bool arg_lost_equation;			/* see bpf_call_needs_frames() */
};

/* callx calls one of the functions whose address is taken. They count as one function. */
struct taken_funcs {
	u16 args;
	u8 needs, ret;
	bool held;
};

struct bpf_precision {
	/* Masks of xregs per insn. The masks of a function are as wide as its stack is deep. */
	struct { u32 first, words; } *func;
	size_t words;
	unsigned long *data_deps, *control_deps, *disjoint_apart;
	/* data_deps, and where only type and object matter */
	unsigned long *type_apart;
	unsigned long *in_frames;		/* see bpf_call_needs_frames() */
	unsigned long *undo;			/* these five before the last partition */
	unsigned long *kept;			/* these five, see keep_precision() */
	/* of the unproven insns of the last pass */
	unsigned long *new_data_deps, *new_control_deps;
	struct taken_funcs taken;		/* see bpf_compute_deps() */
	/* this pass, and the last pass whose partition was kept */
	struct precision_per_pass this_pass, last_pass;
	/* bitmaps of insns */
	unsigned long *held_insns;		/* see reads_held() */
	unsigned long *bad_value_insns;		/* unproven, its value is possibly the cause */
	unsigned long *last_unproven_insns;	/* in the last pass */
	unsigned long *bad_read_insns_done;
	unsigned long *earlier_unproven_insns;	/* in an earlier pass */
	unsigned long *control_seeds, *controlled_insns, *controlled_insns_done, *def_insns;
	u32 first_unproven_insn;	/* of the last pass */
	u32 last_unproven_left;		/* last_unproven_insns whose check did not fail again */
	struct bpf_loop **loops;
	u32 loop_cnt;
	u64 start_cost, pass_cost;	/* env->cost before the pass, the cost of a pass */
	/* the cost that a partition can add to it, and that this one can add */
	u64 budget, budget_left;
	u64 good_budget;		/* see bpf_restore_precision() */
	u8 partitioned_by, too_costly;	/* bits of PARTITION_* */
	bool failing_path_due;		/* see bpf_failing_path_is_due() */
	bool budget_grew;		/* see partition_next() */
	bool new_nospec;
	/* see bpf_hash_live_types() */
	u64 live_types_cost, live_types_mem, start_mem;
	bool live_types_over, join_live_types;	/* in this pass, in all next passes */

	u16 *apart_xregno;	/* per insn, see bpf_range_of_data_dep() */

	/* The path-sensitive run */
	unsigned long *err_insns;		/* insns at which the failing path can end */
	u32 *hops_to_err, *hops_to_exit;	/* per insn, see compute_hops() */
	u64 *seen;				/* hash set, see bpf_failing_path_was_here() */
	u32 seen_cnt, seen_bits;
	unsigned long *loop_control_deps;	/* see bpf_jumps_see_same() */
	u32 loop_control_deps_for, new_data_deps_for;
	u32 loop_carried_at;
	unsigned long loop_carried[XREG_WORDS];
};

struct state_cmp {
	struct bpf_reg_state tmp[2];
	u32 all, data_deps, cnt;
	u32 disjoint_xregno;		/* an xreg of data_deps in the top frame, plus one */
	u32 disjoint_apart;		/* what differs in these xregs */
};

enum {
	PARTITION_ADD_DEPS, PARTITION_PEEL, PARTITION_PEELED_APART, PARTITION_TRANSITIVE_DEPS,
	PARTITION_DISJOINT_APART, PARTITION_LOOP_DISJOINT_APART, PARTITION_PEEL_MORE,
	PARTITION_IN_FRAMES,
	PARTITION_TOO_COSTLY,	/* in bpf_loop.tried */
};

u32 bpf_frame_mask(struct bpf_verifier_env *env, unsigned long *masks,
		   const struct bpf_verifier_state *st, u32 fr, unsigned long *out);
const struct bpf_reg_state *bpf_xreg_value(struct bpf_verifier_env *env,
					   const struct bpf_func_state *f, u32 xregno,
					   struct bpf_reg_state *tmp);
void bpf_compare_states(struct bpf_verifier_env *env, const struct bpf_verifier_state *old,
			const struct bpf_verifier_state *new, unsigned long *only,
			const struct bpf_loop *iv_loop, struct state_cmp *cmp);
int bpf_compute_deps(struct bpf_verifier_env *env, unsigned long *masks,
		     const unsigned long *seed_insns);

static inline bool bpf_calls_function(struct bpf_verifier_env *env, int idx)
{
	struct bpf_insn *insn = &env->prog->insnsi[idx];

	return bpf_pseudo_call(insn) || bpf_is_callx(insn) ||
	       env->insn_aux_data[idx].calls_callback || bpf_is_async_callback_calling_insn(insn);
}

/* Word @i of a mask of xregs that has @slots */
static inline unsigned long bpf_slots_to_xreg_word(const unsigned long *slots, u32 i)
{
	return (i < BITS_TO_LONGS(MAX_BPF_STACK_SLOTS) ? slots[i] << MAX_BPF_EXT_REG : 0) |
	       (i ? slots[i - 1] >> (BITS_PER_LONG - MAX_BPF_EXT_REG) : 0);
}

static inline void bpf_add_slots(unsigned long *mask, const unsigned long *slots, u32 bits)
{
	u32 i;

	for (i = 0; i < BITS_TO_LONGS(bits); i++)
		mask[i] |= bpf_slots_to_xreg_word(slots, i);
}

#endif
