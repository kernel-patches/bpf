/* SPDX-License-Identifier: GPL-2.0-only */
/* What precision.c and failing_path.c share */
#ifndef __BPF_PRECISION_H
#define __BPF_PRECISION_H

#include <linux/bpf_verifier.h>

/* What a pass finds about its errors */
struct precision_per_pass {
	/* bitmaps of insns */
	unsigned long *unproven_insns;
	unsigned long *call_insns;		/* lead to unproven insns, or write what is held */
	unsigned long *bad_read_insns;		/* unproven because of an unreadable xreg */
	unsigned long *unproven_funcs;		/* of functions */
	u64 suspect_loops, first_suspect_loops;	/* of the unproven states, of the first one */
};

struct bpf_precision {
	/* this pass, and the last pass whose partition was kept */
	struct precision_per_pass this_pass, last_pass;
	unsigned long *bad_value_insns;		/* unproven, its value is possibly the cause */
	unsigned long *last_unproven_insns;	/* in the last pass */
	unsigned long *bad_read_insns_done;
	u32 last_unproven_left;		/* last_unproven_insns whose check did not fail again */
	bool new_nospec;

	/* The path-sensitive run */
	unsigned long *err_insns;		/* insns at which the failing path can end */
};

static inline bool bpf_calls_function(struct bpf_verifier_env *env, int idx)
{
	struct bpf_insn *insn = &env->prog->insnsi[idx];

	return bpf_pseudo_call(insn) || bpf_is_callx(insn) ||
	       env->insn_aux_data[idx].calls_callback || bpf_is_async_callback_calling_insn(insn);
}

#endif
