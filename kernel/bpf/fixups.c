// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/bpf_verifier.h>
#include <linux/filter.h>
#include <linux/vmalloc.h>
#include <linux/perf_event.h>
#include <linux/sched/signal.h>
#include <net/xdp.h>
#include "disasm.h"

#define verbose(env, fmt, args...) bpf_verifier_log_write(env, fmt, ##args)

/*
 * Matches BPF_PROBE_ATOMIC too: bpf_convert_ctx_accesses() rewrites arena
 * atomics before bpf_opt_subreg_zext_lo32_rnd_hi32() runs.
 */
static bool is_cmpxchg_insn(const struct bpf_insn *insn)
{
	return BPF_CLASS(insn->code) == BPF_STX &&
	       (BPF_MODE(insn->code) == BPF_ATOMIC ||
		BPF_MODE(insn->code) == BPF_PROBE_ATOMIC) &&
	       insn->imm == BPF_CMPXCHG;
}

/* Returns true if 'insn' is an address space cast instruction translated as BPF_ALU op */
static bool is_addr_space_cast32(struct bpf_prog *prog, const struct bpf_insn *insn)
{
	struct bpf_map *arena = (struct bpf_map *)prog->aux->arena;

	if (insn->code != (BPF_ALU64 | BPF_MOV | BPF_X) || insn->off != BPF_ADDR_SPACE_CAST)
		return false;

	/* cast from as(1) to as(0) */
	if (insn->imm == 1)
		return true;

	/* cast from as(0) to as(1) */
	if (insn->imm == 1 << 16)
		return arena && arena->map_flags & BPF_F_NO_USER_CONV;

	/* non-BPF_F_NO_USER_CONV cast from as(0) to as(1) should be handled by JIT */
	return false;
}

/* Return the regno defined by the insn, or -1. */
static int insn_def_regno(const struct bpf_insn *insn)
{
	switch (BPF_CLASS(insn->code)) {
	case BPF_JMP:
	case BPF_JMP32:
	case BPF_ST:
		return -1;
	case BPF_STX:
		return bpf_atomic_load_reg(insn);
	default:
		return insn->dst_reg;
	}
}

/*
 * For use only in combination with insn_def_regno() >= 0.
 * Returns TRUE if the destination register operates on 64-bit,
 * otherwise return FALSE.
 */
static bool bpf_is_reg64(struct bpf_prog *prog, struct bpf_insn *insn)
{
	u8 class = BPF_CLASS(insn->code);
	u8 mode = BPF_MODE(insn->code);
	u8 size = BPF_SIZE(insn->code);
	u8 op = BPF_OP(insn->code);
	bool mode_mem;

	/* subregister endiness swap */
	if ((class == BPF_ALU || class == BPF_ALU64) && op == BPF_END && insn->imm != 64)
		return false;

	/* w0 += 1 */
	if (class == BPF_ALU && op != BPF_END)
		return false;

	/* address space casts converted to BPF_ALU, see bpf_do_misc_fixups() */
	if (is_addr_space_cast32(prog, insn))
		return false;

	/* non 64-bit, non signed extended loads */
	mode_mem = mode == BPF_MEM || mode == BPF_PROBE_MEM || mode == BPF_PROBE_MEM32;
	if (class == BPF_LDX && mode_mem && size != BPF_DW)
		return false;

	/* atomics, see insn_def_regno() */
	if (class == BPF_STX && size != BPF_DW)
		return false;

	/* both LD_IND and LD_ABS return 32-bit data. */
	if (class == BPF_LD && (mode == BPF_IND || mode == BPF_ABS))
		return false;

	/* Conservatively return true at default. */
	return true;
}

/*
 * Return the 32-bit subregister defined by INSN, or -1 if INSN does not
 * explicitly define a 32-bit value.
 */
int bpf_insn_def32(struct bpf_prog *prog, struct bpf_insn *insn)
{
	int dst_reg = insn_def_regno(insn);

	if (dst_reg < 0 || bpf_is_reg64(prog, insn))
		return -1;

	return dst_reg;
}

const struct btf_func_model *
bpf_jit_find_kfunc_model(const struct bpf_prog *prog,
			 const struct bpf_insn *insn)
{
	const struct bpf_kfunc_desc *res;
	struct bpf_kfunc_desc_tab *tab;

	tab = prog->aux->kfunc_tab;
	if (insn->off < 0 || insn->off >= tab->nr_descs)
		return NULL;

	res = &tab->descs[insn->off];
	if (bpf_jit_supports_far_kfunc_call()) {
		if (res->func_id != insn->imm)
			return NULL;
	} else if ((s32)BPF_CALL_IMM(res->addr) != insn->imm) {
		return NULL;
	}

	return &res->func_model;
}

static int add_kfunc_in_insns(struct bpf_verifier_env *env,
			      struct bpf_insn *insn, int cnt)
{
	int i, ret;

	for (i = 0; i < cnt; i++, insn++) {
		if (bpf_pseudo_kfunc_call(insn)) {
			ret = bpf_add_kfunc_call(env, insn->imm, insn->off);
			if (ret < 0)
				return ret;
		}
	}
	return 0;
}

#ifndef CONFIG_BPF_JIT_ALWAYS_ON
static int get_callee_stack_depth(struct bpf_verifier_env *env,
				  const struct bpf_insn *insn, int idx)
{
	int start = idx + insn->imm + 1, subprog;

	subprog = bpf_find_subprog(env, start);
	if (verifier_bug_if(subprog < 0, env, "get stack depth: no program at insn %d", start))
		return -EFAULT;
	return env->subprog_info[subprog].stack_depth;
}
#endif

enum bpf_patch_mode {
	BPF_PATCH_KEEP_TARGET,	/* targets of 'off' keep naming 'off', the first new insn */
	BPF_PATCH_MOVE_TARGET,	/* targets of 'off' follow the original insn to 'off + len - 1' */
};

/* single env->prog->insni[off] instruction was replaced with the range
 * insni[off, off + cnt).  Adjust corresponding insn_aux_data by copying
 * [0, off) and [off, end) to new locations, so the patched range stays zero
 */
static void adjust_insn_aux_data(struct bpf_verifier_env *env,
				 struct bpf_prog *new_prog, u32 off, u32 cnt,
				 struct bpf_insn *original_insn,
				 enum bpf_patch_mode mode)
{
	struct bpf_insn_aux_data *data = env->insn_aux_data;
	struct bpf_insn *insn = new_prog->insnsi;
	u32 old_seen = data[off].seen;
	u32 prog_len;
	int i;

	/* aux info at OFF always needs adjustment, no matter fast path
	 * (cnt == 1) is taken or not. There is no guarantee INSN at OFF is the
	 * original insn at old prog.
	 */
	data[off].zext_dst = bpf_insn_def32(new_prog, insn + off + cnt - 1) >= 0;

	if (cnt == 1) {
		/*
		 * A non-memory accessing insn could have been replaced by a
		 * memory accessing insn, systematically mark it for non-stack
		 * access
		 */
		data[off].non_stack_access = bpf_is_mem_insn(insn + off);
		return;
	}
	prog_len = new_prog->len;
	env->insn_aux_data_len = prog_len;

	memmove(data + off + cnt - 1, data + off,
		sizeof(struct bpf_insn_aux_data) * (prog_len - off - cnt + 1));
	memset(data + off, 0, sizeof(struct bpf_insn_aux_data) * (cnt - 1));
	for (i = off; i < off + cnt - 1; i++) {
		/* Expand insni[off]'s seen count to the patched range. */
		data[i].seen = old_seen;
		data[i].zext_dst = bpf_insn_def32(new_prog, insn + i) >= 0;
		/*
		 * In BPF_PATCH_MOVE_TARGET mode the original insn is the last
		 * slot by construction.
		 */
		if (mode == BPF_PATCH_KEEP_TARGET &&
		    !memcmp(insn + i, original_insn, sizeof(struct bpf_insn))) {
			data[i].non_stack_access =
				data[off + cnt - 1].non_stack_access;
			data[off + cnt - 1].non_stack_access = false;
		} else if (bpf_is_mem_insn(insn + i)) {
			data[i].non_stack_access = true;
		}
	}

	/*
	 * Last slot instruction could be a newly generated
	 * BPF_ST/BPF_LDX/BPF_STX, systematically mark it for non-stack access
	 * if it is not the original instruction, otherwise keep the
	 * original marking
	 */
	if (bpf_is_mem_insn(insn + off + cnt - 1) &&
	    memcmp(insn + off + cnt - 1, original_insn, sizeof(struct bpf_insn)))
		data[off + cnt - 1].non_stack_access = true;

	/*
	 * The indirect_target flag of the original instruction was moved to the last of the
	 * new instructions by the above memmove and memset, but the indirect jump target is
	 * actually the first instruction, so move it back. This also matches with the behavior
	 * of bpf_insn_array_adjust(), which preserves xlated_off to point to the first new
	 * instruction. For BPF_PATCH_MOVE_TARGET the original instruction is the last one,
	 * so the flag already sits where needed.
	 */
	if (mode == BPF_PATCH_KEEP_TARGET && data[off + cnt - 1].indirect_target) {
		data[off].indirect_target = 1;
		data[off + cnt - 1].indirect_target = 0;
	}
}

static void adjust_subprog_starts(struct bpf_verifier_env *env, u32 off, u32 len)
{
	int i;

	if (len == 1)
		return;
	/* NOTE: fake 'exit' subprog should be updated as well. */
	for (i = 0; i <= env->subprog_cnt; i++) {
		if (env->subprog_info[i].start <= off)
			continue;
		env->subprog_info[i].start += len - 1;
	}
}

static void adjust_insn_arrays(struct bpf_verifier_env *env, u32 first, u32 len)
{
	int i;

	if (len == 1)
		return;

	for (i = 0; i < env->insn_array_map_cnt; i++)
		bpf_insn_array_adjust(env->insn_array_maps[i], first, len);
}

static void adjust_insn_arrays_after_remove(struct bpf_verifier_env *env, u32 off, u32 len)
{
	int i;

	for (i = 0; i < env->insn_array_map_cnt; i++)
		bpf_insn_array_adjust_after_remove(env->insn_array_maps[i], off, len);
}

static void adjust_poke_descs(struct bpf_prog *prog, u32 first, u32 len)
{
	struct bpf_jit_poke_descriptor *tab = prog->aux->poke_tab;
	int i, sz = prog->aux->size_poke_tab;
	struct bpf_jit_poke_descriptor *desc;

	for (i = 0; i < sz; i++) {
		desc = &tab[i];
		if (desc->insn_idx < first)
			continue;
		desc->insn_idx += len - 1;
	}
}

/*
 * Some post-verification instruction rewriting passes require an
 * O(prog->len) operation per instruction. Keep their shared primitives
 * killable and preemptible.
 */
static bool bpf_rewrite_must_abort(void)
{
	if (fatal_signal_pending(current))
		return true;
	cond_resched();
	return false;
}

static struct bpf_prog *__bpf_patch_insn_data(struct bpf_verifier_env *env, u32 off,
					      const struct bpf_insn *patch, u32 len,
					      enum bpf_patch_mode mode)
{
	struct bpf_prog *new_prog;
	struct bpf_insn_aux_data *new_data = NULL;
	/* The first slot whose targets move. */
	u32 first = mode == BPF_PATCH_MOVE_TARGET ? off : off + 1;
	struct bpf_insn original_insn;

	if (bpf_rewrite_must_abort())
		return NULL;

	if (len > 1) {
		new_data = vrealloc(env->insn_aux_data,
				    array_size(env->prog->len + len - 1,
					       sizeof(struct bpf_insn_aux_data)),
				    GFP_KERNEL_ACCOUNT | __GFP_ZERO);
		if (!new_data)
			return NULL;

		env->insn_aux_data = new_data;
	}

	memcpy(&original_insn, env->prog->insnsi + off, sizeof(struct bpf_insn));
	new_prog = bpf_patch_insn_single(env->prog, off, patch, len);
	if (IS_ERR(new_prog)) {
		if (PTR_ERR(new_prog) == -ERANGE)
			verbose(env,
				"insn %d cannot be patched due to 16-bit range\n",
				env->insn_aux_data[off].orig_idx);
		return NULL;
	}
	adjust_insn_aux_data(env, new_prog, off, len, &original_insn, mode);
	adjust_subprog_starts(env, off, len);
	adjust_insn_arrays(env, first, len);
	bpf_adjust_func_ptrs(env, off, len);
	adjust_poke_descs(new_prog, first, len);
	return new_prog;
}

struct bpf_prog *bpf_patch_insn_data(struct bpf_verifier_env *env, u32 off,
				     const struct bpf_insn *patch, u32 len)
{
	return __bpf_patch_insn_data(env, off, patch, len, BPF_PATCH_KEEP_TARGET);
}

/*
 * insn was moved down by delta insns inside its own patch. Operands relative
 * to the pc that point in front of the old position did not move with it.
 */
static int bpf_adj_moved_insn(struct bpf_insn *insn, u32 delta)
{
	u8 class = BPF_CLASS(insn->code), op = BPF_OP(insn->code);
	s64 off = insn->imm, off_min = S32_MIN;
	bool is_imm = true;

	if (bpf_pseudo_func(insn) || bpf_pseudo_call(insn)) {
		/* subprog that started at the old position starts with the patch */
		if (off >= 0)
			return 0;
	} else if ((class == BPF_JMP || class == BPF_JMP32) &&
		   op != BPF_CALL && op != BPF_EXIT) {
		if (insn->code != (BPF_JMP32 | BPF_JA)) {
			off = insn->off;
			off_min = S16_MIN;
			is_imm = false;
		}
		/* jump to itself stays */
		if (off >= -1)
			return 0;
	} else {
		return 0;
	}

	off -= delta;
	if (off < off_min)
		return -ERANGE;
	if (is_imm)
		insn->imm = off;
	else
		insn->off = off;
	return 0;
}

static bool jumps_to_itself(const struct bpf_insn *insn)
{
	u8 class = BPF_CLASS(insn->code), op = BPF_OP(insn->code);

	return (class == BPF_JMP || class == BPF_JMP32) && op != BPF_CALL && op != BPF_EXIT &&
	       insn->code != (BPF_JMP32 | BPF_JA) && insn->off == -1;
}

/* How a subprog leaves when it is out of budget, see push_budget_exit() */
static struct bpf_insn budget_exit_insn(struct bpf_verifier_env *env, struct bpf_subprog_info *sub)
{
	if (!sub->bail_unwinds)
		return BPF_EXIT_INSN();
	sub->can_unwind = true;
	env->prog->jit_required = 1;
	return BPF_RAW_INSN(BPF_JMP | BPF_EXIT, 0, BPF_UNWIND_EXIT, 0, 0);
}

/*
 * may_goto has 16 bits for the offset, and what is between it and its target is going
 * to grow: may_goto itself becomes 7 insns.
 */
#define BPF_GUARD_NEAR	4096

static bool guard_leaves_subprog(const struct bpf_insn_aux_data *aux)
{
	return aux->loop_guard && !aux->guard_no_unwind;
}

/*
 * 'r0 = 0; exit' behind the last insn of the subprog, for all its guards that are near.
 * Returns the number of insns that were added.
 */
static int append_budget_exit(struct bpf_verifier_env *env, int s)
{
	struct bpf_subprog_info *sub = &env->subprog_info[s];
	int last = (sub + 1)->start - 1, n = 0, i;
	struct bpf_prog *new_prog;
	struct bpf_insn buf[4];

	for (i = max_t(int, sub->start, last + 1 - BPF_GUARD_NEAR); i <= last; i++)
		if (guard_leaves_subprog(&env->insn_aux_data[i]))
			break;
	if (i > last)
		return 0;

	buf[n++] = env->prog->insnsi[last];
	buf[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
	if (bpf_ret_reg_pair(env, s))
		buf[n++] = BPF_MOV64_IMM(BPF_REG_2, 0);
	buf[n++] = budget_exit_insn(env, sub);
	new_prog = bpf_patch_insn_data(env, last, buf, n);
	if (!new_prog)
		return -ENOMEM;
	env->prog = new_prog;
	/* the original insn is the first one of the patch, not the last one */
	swap(env->insn_aux_data[last], env->insn_aux_data[last + n - 1]);
	for (i = last + 1; i < last + n; i++)
		env->insn_aux_data[i].seen = 1;
	return n - 1;
}

/*
 * Add may_goto in front of the insns that the main pass marked, see
 * check_loop_guard(). It verified the edge from the insn to where may_goto goes.
 */
int bpf_insert_loop_guards(struct bpf_verifier_env *env)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	int len = env->prog->len, i, r, s, to, n, jmp, delta = 0, err = 0;
	struct bpf_insn *patch;
	struct bpf_prog *new_prog;
	u32 *before;
	int *target, *leave, *moved;
	u16 *zero;
	u64 *slots;
	s64 off;

	for (i = 0; i < len; i++)
		if (aux[i].loop_guard)
			break;
	if (i == len)
		return 0;

	/*
	 * Where the subprog has 'r0 = 0; exit', 0 if it has none. And how far that moved
	 * the subprog: guard_to is from the time before.
	 */
	leave = kvcalloc(2 * env->subprog_cnt, sizeof(int), GFP_KERNEL_ACCOUNT);
	if (!leave)
		return -ENOMEM;
	moved = leave + env->subprog_cnt;
	for (s = env->subprog_cnt - 1; s >= 0; s--) {
		leave[s] = append_budget_exit(env, s);
		if (leave[s] < 0) {
			err = leave[s];
			kvfree(leave);
			return err;
		}
	}
	for (s = 0, n = 0; s < env->subprog_cnt; s++) {
		moved[s] = n;
		n += leave[s];
		if (leave[s])
			leave[s] = env->subprog_info[s + 1].start - leave[s];
	}
	aux = env->insn_aux_data;
	len = env->prog->len;

	/* the number of insns added in front of the insn, where the guard of the insn goes */
	before = kvcalloc(len + 1, sizeof(u32), GFP_KERNEL_ACCOUNT);
	target = kvcalloc(len, sizeof(int), GFP_KERNEL_ACCOUNT);
	zero = kvcalloc(len, sizeof(u16), GFP_KERNEL_ACCOUNT);
	slots = kvcalloc(len, sizeof(u64), GFP_KERNEL_ACCOUNT);
	patch = kvcalloc(80, sizeof(*patch), GFP_KERNEL_ACCOUNT);
	if (!before || !target || !zero || !slots || !patch) {
		err = -ENOMEM;
		goto out;
	}
	for (i = 0; i < len; i++) {
		s = bpf_find_containing_subprog(env, i) - env->subprog_info;
		target[i] = aux[i].loop_guard ? aux[i].guard_to + moved[s] : -1;
		zero[i] = aux[i].loop_guard ? aux[i].guard_zero : 0;
		slots[i] = aux[i].loop_guard ? aux[i].guard_zero_slots : 0;
		if (guard_leaves_subprog(&aux[i])) {
			/* see push_budget_exit() */
			slots[i] = 0;
			if (leave[s] && leave[s] - i <= BPF_GUARD_NEAR) {
				target[i] = leave[s];
				zero[i] = 0;
			} else {
				target[i] = -2;
				zero[i] = BIT(BPF_REG_0);
				if (bpf_ret_reg_pair(env, s))
					zero[i] |= BIT(BPF_REG_2);
			}
		}
		before[i + 1] = before[i];
		if (aux[i].loop_guard)
			before[i + 1] += zero[i] || slots[i] ?
					 3 + hweight16(zero[i]) + hweight64(slots[i]) : 1;
	}

	for (i = 0; i < len; i++) {
		to = target[i];
		if (to == -1)
			continue;
		/*
		 *	may_goto to		or	may_goto +1
		 *	insn				goto +N
		 *					rX = 0, ...
		 *					goto to, or exit
		 *					insn
		 */
		n = 0;
		if (zero[i] || slots[i]) {
			patch[n++] = BPF_RAW_INSN(BPF_JMP | BPF_JCOND, 0, 0, 1, 0);
			patch[n++] = BPF_JMP_A(hweight16(zero[i]) + hweight64(slots[i]) + 1);
			for (r = BPF_REG_0; r < BPF_REG_FP; r++)
				if (zero[i] & BIT(r))
					patch[n++] = BPF_MOV64_IMM(r, 0);
			for (r = 0; r < 64; r++)
				if (slots[i] & BIT_ULL(r))
					patch[n++] = BPF_ST_MEM(BPF_DW, BPF_REG_FP,
								-(r + 1) * BPF_REG_SIZE, 0);
		}
		jmp = n++;
		/*
		 * What is behind moves with this patch and is adjusted by
		 * the patches to come. What is in front is where it is going to be.
		 */
		if (to == -2)
			off = 0;
		else if (to > i)
			off = to - i + n - jmp - 1;
		else
			off = (s64)to + before[to] - (i + delta + jmp) - 1;
		if (!zero[i] && !slots[i] && (off > S16_MAX || off < S16_MIN)) {
			verbose(env, "exit of the loop is too far from insn %d for may_goto\n", i);
			err = -ERANGE;
			break;
		}
		patch[jmp] = zero[i] || slots[i] ? BPF_JMP32_A(off) :
			     BPF_RAW_INSN(BPF_JMP | BPF_JCOND, 0, 0, off, 0);
		if (to == -2)
			patch[jmp] = budget_exit_insn(env, bpf_find_containing_subprog(env,
										      i + delta));
		patch[n] = env->prog->insnsi[i + delta];
		/* A jump to itself is a back edge. It goes through may_goto like the others. */
		if (jumps_to_itself(&patch[n]))
			patch[n].off -= n;
		else
			err = bpf_adj_moved_insn(&patch[n], n);
		if (err) {
			verbose(env, "insn %d cannot be patched due to 16-bit range\n", i);
			break;
		}
		n++;
		new_prog = bpf_patch_insn_data(env, i + delta, patch, n);
		if (!new_prog) {
			err = -ENOMEM;
			break;
		}
		env->prog = new_prog;
		delta += n - 1;
	}
out:
	kvfree(leave);
	kvfree(before);
	kvfree(target);
	kvfree(zero);
	kvfree(slots);
	kvfree(patch);
	return err;
}

/*
 * For all jmp insns in a given 'prog' that point to 'tgt_idx' insn adjust the
 * jump offset by 'delta'.
 */
static int adjust_jmp_off(struct bpf_prog *prog, u32 tgt_idx, u32 delta)
{
	struct bpf_insn *insn = prog->insnsi;
	u32 insn_cnt = prog->len, i;
	s32 imm;
	s16 off;

	for (i = 0; i < insn_cnt; i++, insn++) {
		u8 code = insn->code;

		if (tgt_idx <= i && i < tgt_idx + delta)
			continue;

		if ((BPF_CLASS(code) != BPF_JMP && BPF_CLASS(code) != BPF_JMP32) ||
		    BPF_OP(code) == BPF_CALL || BPF_OP(code) == BPF_EXIT)
			continue;

		if (insn->code == (BPF_JMP32 | BPF_JA)) {
			if (i + 1 + insn->imm != tgt_idx)
				continue;
			if (check_add_overflow(insn->imm, delta, &imm))
				return -ERANGE;
			insn->imm = imm;
		} else {
			if (i + 1 + insn->off != tgt_idx)
				continue;
			if (check_add_overflow(insn->off, delta, &off))
				return -ERANGE;
			insn->off = off;
		}
	}
	return 0;
}

/*
 * The room that the frame of a subprog takes besides its stack: what JIT saves at most.
 * arm64: FP, LR, 8 registers, the tail call count: 96. loongarch: 96, riscv: 80.
 * powerpc: 112 with ELF ABI v2, 192 with v1.
 */
#define BPF_FRAME_OVERHEAD	(IS_ENABLED(CONFIG_PPC64) ? 192 : 96)

/* the room for the frames of recursive subprogs */
#define BPF_RECURSION_STACK	4096
/* the frames of the helper or the kfunc that is between a callback and its caller */
#define BPF_CALLBACK_OVERHEAD	256

static u32 recursive_frame_size(struct bpf_verifier_env *env, int s)
{
	struct bpf_subprog_info *sub = &env->subprog_info[s];
	struct bpf_insn *insn = env->prog->insnsi;
	u32 size, used = 0, may_goto = 0, cb = sub->is_cb ? BPF_CALLBACK_OVERHEAD : 0;
	int i;

	/* may_goto is yet to add its 16 bytes */
	if (!IS_ENABLED(CONFIG_X86_64))
		return round_up(sub->stack_depth + 16, 32) + BPF_FRAME_OVERHEAD + cb +
		       sub->max_out_stack_arg_cnt * BPF_REG_SIZE;

	for (i = sub->start; i < (sub + 1)->start; i++) {
		if (insn[i].dst_reg >= BPF_REG_6 && insn[i].dst_reg <= BPF_REG_9)
			used |= BIT(insn[i].dst_reg);
		if (insn[i].src_reg >= BPF_REG_6 && insn[i].src_reg <= BPF_REG_9)
			used |= BIT(insn[i].src_reg);
		if (bpf_is_may_goto_insn(&insn[i]))
			may_goto = 16;
	}
	/* the return address, rbp, the registers that are saved */
	size = 16 + hweight32(used) * 8;
	/* the base of arena, the slot for r12 */
	if (env->prog->aux->arena)
		size += 16;
	/* the tail call count and the pointer to it */
	if (sub->tail_call_reachable)
		size += 16;
	return size + cb + round_up(sub->stack_depth + may_goto, 8) +
	       sub->max_out_stack_arg_cnt * BPF_REG_SIZE;
}

/* what the frames of recursive subprogs add up to at most */
#define BPF_RECURSION_UNITS	65536

/*
 * How deep a recursion goes is not known, so it is counted at run time. In the same
 * spirit as may_goto: the program goes on for as long as there is budget and
 * takes a way out that was verified when there is none.
 *
 * Every subprog on a cycle of the call graph adds its weight to a per-cpu
 * counter of the program when it is entered and takes it back at every exit.
 * The weight is the part of the budget that its frame takes: of the stack
 * room, or of the room in the stack in arena, whichever is larger. So these
 * frames take no more than BPF_RECURSION_STACK, on top of the chain of calls
 * without recursion that check_max_stack_depth() looked at.
 *
 * A subprog that calls itself twice doesn't have to go deep to go on forever. So
 * the calls are counted too: BPF_MAX_LOOPS of them in a run of the prog, like the
 * callbacks of bpf_loop(). Once they are used up every call returns at once, and
 * the frames that are there come to an end.
 *
 * Another run of the program on the same cpu, in interrupt or after
 * preemption, counts in the same counter. Then there is less for both.
 */
int bpf_insert_recursion_checks(struct bpf_verifier_env *env)
{
	struct bpf_subprog_info *si = env->subprog_info;
	u32 frame, min_frame = U32_MAX, arena_frame = 0, arena_room = 0, weight;
	u32 limit = BPF_RECURSION_STACK;
	struct bpf_insn buf[24], first;
	struct bpf_prog *new_prog;
	struct bpf_recursion_budget __percpu *depth;
	/* Only this cpu touches the counters */
	int fetch_add = BPF_ADD | BPF_FETCH |
			(bpf_jit_supports_local_atomics() ? BPF_ATOMIC_LOCAL : 0);
	int i, s, n, bail, bail_len, err;

	for (s = 0; s < env->subprog_cnt; s++) {
		if (!si[s].recursive)
			continue;
		frame = recursive_frame_size(env, s);
		si[s].recursion_weight = DIV_ROUND_UP(frame * BPF_RECURSION_UNITS, limit);
		min_frame = min(min_frame, frame);
		arena_frame = max(arena_frame, si[s].arena_stack_depth);
	}
	if (min_frame == U32_MAX)
		return 0;
	if (arena_frame) {
		/*
		 * One more frame is for the subprog that finds that there is no
		 * budget: it has its frame by then.
		 */
		u32 room = BPF_ARENA_STACK_MAX - env->max_arena_stack_depth;

		if (room < 2 * arena_frame) {
			verbose(env, "no room in the stack in arena for recursion\n");
			return -EACCES;
		}
		/* no more than the frames that fit in the stack can take */
		arena_room = min(room - arena_frame, limit / min_frame * arena_frame);
		env->max_arena_stack_depth += arena_room + arena_frame;
	}
	for (s = 0; s < env->subprog_cnt; s++) {
		if (!si[s].recursive)
			continue;
		if (si[s].arena_stack_depth)
			si[s].recursion_weight = max(si[s].recursion_weight,
						     DIV_ROUND_UP(si[s].arena_stack_depth *
								  BPF_RECURSION_UNITS, arena_room));
		if (si[s].recursion_weight > BPF_RECURSION_UNITS) {
			verbose(env, "the frame of recursive %s() is too large\n",
				bpf_subprog_name(env, s));
			return -EACCES;
		}
	}

	depth = alloc_percpu_gfp(struct bpf_recursion_budget, GFP_KERNEL_ACCOUNT);
	if (!depth)
		return -ENOMEM;
	env->prog->aux->call_depth = depth;
	env->prog->jit_required = 1;

	/* From the last one, so that nothing moves in those that are yet to be done. */
	for (s = env->subprog_cnt - 1; s > 0; s--) {
		if (!si[s].recursive)
			continue;
		/*
		 * R0 has nothing at the entry. The address is not for AX:
		 * blinding of constants takes ld_imm64 apart with the help of
		 * AX. It leaves alone the insns that have AX in them.
		 */
		n = 0;
		first = env->prog->insnsi[si[s].start];
		/* The exit drops the frame in the stack in arena. Take it before the check. */
		if (is_arena_sp_adj(&first)) {
			buf[n++] = first;
			first = BPF_JMP_A(0);
		}
		memcpy(buf + n, (struct bpf_insn[]){ BPF_LD_IMM64(BPF_REG_0, (long)depth) },
		       2 * sizeof(buf[0]));
		n += 2;
		buf[n++] = BPF_MOV64_PERCPU_REG(BPF_REG_0, BPF_REG_0);
		weight = si[s].recursion_weight;
		bail_len = bpf_ret_reg_pair(env, s) ? 3 : 2;
		buf[n++] = BPF_MOV64_IMM(BPF_REG_AX, weight);
		buf[n++] = BPF_ATOMIC_OP(BPF_W, fetch_add, BPF_REG_0, BPF_REG_AX,
					 offsetof(struct bpf_recursion_budget, depth));
		buf[n++] = BPF_JMP_IMM(BPF_JGT, BPF_REG_AX, BPF_RECURSION_UNITS - weight, 3);
		buf[n++] = BPF_MOV64_IMM(BPF_REG_AX, 1);
		buf[n++] = BPF_ATOMIC_OP(BPF_W, fetch_add, BPF_REG_0, BPF_REG_AX,
					 offsetof(struct bpf_recursion_budget, calls));
		buf[n++] = BPF_JMP_IMM(BPF_JLT, BPF_REG_AX, BPF_MAX_LOOPS, bail_len);
		bail = n;
		buf[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
		if (bpf_ret_reg_pair(env, s))
			buf[n++] = BPF_MOV64_IMM(BPF_REG_2, 0);
		buf[n++] = budget_exit_insn(env, &si[s]);
		buf[n] = first;
		err = bpf_adj_moved_insn(&buf[n], n);
		if (err) {
			verbose(env, "insn %d cannot be patched due to 16-bit range\n",
				env->insn_aux_data[si[s].start].orig_idx);
			return err;
		}
		n++;
		new_prog = __bpf_patch_insn_data(env, si[s].start, buf, n, BPF_PATCH_MOVE_TARGET);
		if (!new_prog)
			return -ENOMEM;
		env->prog = new_prog;
		env->insn_aux_data[si[s].start + bail].recursion_bail = true;
		/* calls get to the check, jumps to the first insn do not */
		err = adjust_jmp_off(env->prog, si[s].start, n - 1);
		if (err)
			return err;
	}

	/*
	 * The calls are counted anew when a run begins. For async callbacks see
	 * bpf_prog_begin_run(). R0 has nothing at the entry.
	 */
	memcpy(buf, (struct bpf_insn[]){ BPF_LD_IMM64(BPF_REG_0, (long)depth) },
	       2 * sizeof(buf[0]));
	buf[2] = BPF_MOV64_PERCPU_REG(BPF_REG_0, BPF_REG_0);
	/* calls and reported */
	buf[3] = BPF_ST_MEM(BPF_DW, BPF_REG_0, 0, 0);
	buf[4] = env->prog->insnsi[0];
	err = bpf_adj_moved_insn(&buf[4], 4);
	if (err) {
		verbose(env, "insn %d cannot be patched due to 16-bit range\n",
			env->insn_aux_data[0].orig_idx);
		return err;
	}
	new_prog = __bpf_patch_insn_data(env, 0, buf, 5, BPF_PATCH_MOVE_TARGET);
	if (!new_prog)
		return -ENOMEM;
	env->prog = new_prog;
	/* a jump to the first insn doesn't begin a run */
	err = adjust_jmp_off(env->prog, 0, 4);
	if (err)
		return err;

	/* R1 is nothing to the caller. Jumps to exit get to what is added. */
	for (i = 0; i < env->prog->len; i++) {
		if (bpf_is_ldimm64(&env->prog->insnsi[i])) {
			i++;
			continue;
		}
		if (env->prog->insnsi[i].code != (BPF_JMP | BPF_EXIT) ||
		    !bpf_find_containing_subprog(env, i)->recursive)
			continue;
		n = 0;
		memcpy(buf, (struct bpf_insn[]){ BPF_LD_IMM64(BPF_REG_1, (long)depth) },
		       2 * sizeof(buf[0]));
		n += 2;
		buf[n++] = BPF_MOV64_PERCPU_REG(BPF_REG_1, BPF_REG_1);
		weight = bpf_find_containing_subprog(env, i)->recursion_weight;
		buf[n++] = BPF_MOV64_IMM(BPF_REG_AX, -(int)weight);
		buf[n++] = BPF_ATOMIC_OP(BPF_W, fetch_add, BPF_REG_1, BPF_REG_AX,
					 offsetof(struct bpf_recursion_budget, depth));
		buf[n++] = env->prog->insnsi[i];
		new_prog = bpf_patch_insn_data(env, i, buf, n);
		if (!new_prog)
			return -ENOMEM;
		env->prog = new_prog;
		i += n - 1;
	}
	return 0;
}

/*
 * Say so when a recursive subprog is out of budget, once in a run: from then on every call
 * comes here. R0 is what bpf_insert_recursion_checks() left in it. The arguments are not
 * needed any more.
 * It's done after bpf_do_misc_fixups(), that takes a call for a call of a helper.
 */
int bpf_insert_recursion_reports(struct bpf_verifier_env *env)
{
	struct bpf_prog *new_prog;
	struct bpf_insn buf[4];
	int i;

	for (i = 0; i < env->prog->len; i++) {
		if (!env->insn_aux_data[i].recursion_bail)
			continue;
		env->insn_aux_data[i].recursion_bail = false;
		buf[0] = BPF_LDX_MEM(BPF_W, BPF_REG_AX, BPF_REG_0,
				     offsetof(struct bpf_recursion_budget, reported));
		buf[1] = BPF_JMP_IMM(BPF_JNE, BPF_REG_AX, 0, 1);
		buf[2] = BPF_EMIT_CALL(bpf_prog_report_recursion);
		buf[3] = env->prog->insnsi[i];
		new_prog = bpf_patch_insn_data(env, i, buf, 4);
		if (!new_prog)
			return -ENOMEM;
		env->prog = new_prog;
		i += 3;
	}
	return 0;
}

/*
 * Say so when the main prog unwinds. JITs make exit of that, see bpf_prog_can_unwind().
 * It's done after bpf_do_misc_fixups(), that takes a call for a call of a helper.
 */
int bpf_insert_unwound_reports(struct bpf_verifier_env *env)
{
	struct bpf_prog *new_prog;
	struct bpf_insn buf[3];
	int i;

	if (env->prog->type == BPF_PROG_TYPE_EXT)
		return 0;
	for (i = 0; i < env->subprog_info[1].start; i++) {
		if (!bpf_is_unwind_exit(&env->prog->insnsi[i]))
			continue;
		buf[0] = BPF_MOV64_REG(BPF_REG_1, BPF_REG_0);
		buf[1] = BPF_EMIT_CALL(bpf_prog_report_unwound);
		buf[2] = env->prog->insnsi[i];
		new_prog = bpf_patch_insn_data(env, i, buf, 3);
		if (!new_prog)
			return -ENOMEM;
		env->prog = new_prog;
		i += 2;
	}
	return 0;
}

static int adjust_subprog_starts_after_remove(struct bpf_verifier_env *env,
					      u32 off, u32 cnt)
{
	int i, j;

	/* find first prog starting at or after off (first to remove) */
	for (i = 0; i < env->subprog_cnt; i++)
		if (env->subprog_info[i].start >= off)
			break;
	/* find first prog starting at or after off + cnt (first to stay) */
	for (j = i; j < env->subprog_cnt; j++)
		if (env->subprog_info[j].start >= off + cnt)
			break;
	/* if j doesn't start exactly at off + cnt, we are just removing
	 * the front of previous prog
	 */
	if (env->subprog_info[j].start != off + cnt)
		j--;

	if (j > i) {
		struct bpf_prog_aux *aux = env->prog->aux;
		int move;

		/* move fake 'exit' subprog as well */
		move = env->subprog_cnt + 1 - j;

		memmove(env->subprog_info + i,
			env->subprog_info + j,
			sizeof(*env->subprog_info) * move);
		env->subprog_cnt -= j - i;

		/* remove func_info and its aux */
		if (aux->func_info) {
			move = aux->func_info_cnt - j;

			memmove(aux->func_info + i,
				aux->func_info + j,
				sizeof(*aux->func_info) * move);
			if (aux->func_info_aux)
				memmove(aux->func_info_aux + i,
					aux->func_info_aux + j,
					sizeof(*aux->func_info_aux) * move);
			aux->func_info_cnt -= j - i;
			/* func_info->insn_off is set after all code rewrites,
			 * in adjust_btf_func() - no need to adjust
			 */
		}
		/* The exception callback is live, so it cannot sit inside the removed range. */
		if (env->exception_callback_subprog >= j)
			env->exception_callback_subprog -= j - i;
	} else {
		/* convert i from "first prog to remove" to "first to adjust" */
		if (env->subprog_info[i].start == off)
			i++;
	}

	/* update fake 'exit' subprog as well */
	for (; i <= env->subprog_cnt; i++)
		env->subprog_info[i].start -= cnt;

	return 0;
}

static int bpf_adj_linfo_after_remove(struct bpf_verifier_env *env, u32 off,
				      u32 cnt)
{
	struct bpf_prog *prog = env->prog;
	u32 i, l_off, l_cnt, nr_linfo;
	struct bpf_line_info *linfo;

	nr_linfo = prog->aux->nr_linfo;
	if (!nr_linfo)
		return 0;

	linfo = prog->aux->linfo;

	/* find first line info to remove, count lines to be removed */
	for (i = 0; i < nr_linfo; i++)
		if (linfo[i].insn_off >= off)
			break;

	l_off = i;
	l_cnt = 0;
	for (; i < nr_linfo; i++)
		if (linfo[i].insn_off < off + cnt)
			l_cnt++;
		else
			break;

	/* First live insn doesn't match first live linfo, it needs to "inherit"
	 * last removed linfo.  prog is already modified, so prog->len == off
	 * means no live instructions after (tail of the program was removed).
	 */
	if (prog->len != off && l_cnt &&
	    (i == nr_linfo || linfo[i].insn_off != off + cnt)) {
		l_cnt--;
		linfo[--i].insn_off = off + cnt;
	}

	/* remove the line info which refer to the removed instructions */
	if (l_cnt) {
		memmove(linfo + l_off, linfo + i,
			sizeof(*linfo) * (nr_linfo - i));

		prog->aux->nr_linfo -= l_cnt;
		nr_linfo = prog->aux->nr_linfo;
	}

	/* pull all linfo[i].insn_off >= off + cnt in by cnt */
	for (i = l_off; i < nr_linfo; i++)
		linfo[i].insn_off -= cnt;

	/* fix up all subprogs (incl. 'exit') which start >= off */
	for (i = 0; i <= env->subprog_cnt; i++)
		if (env->subprog_info[i].linfo_idx > l_off) {
			/* program may have started in the removed region but
			 * may not be fully removed
			 */
			if (env->subprog_info[i].linfo_idx >= l_off + l_cnt)
				env->subprog_info[i].linfo_idx -= l_cnt;
			else
				env->subprog_info[i].linfo_idx = l_off;
		}

	return 0;
}

/* Clean up dynamically allocated fields of aux data for instructions [start, ...] */
void bpf_clear_insn_aux_data(struct bpf_verifier_env *env, int start, int len)
{
	struct bpf_insn_aux_data *aux_data = env->insn_aux_data;
	int end = start + len;
	int i;

	for (i = start; i < end; i++) {
		if (aux_data[i].loop) {
			kvfree(aux_data[i].loop->exits);
			kvfree(aux_data[i].loop);
			aux_data[i].loop = NULL;
		}
	}
}

static int verifier_remove_insns(struct bpf_verifier_env *env, u32 off, u32 cnt)
{
	struct bpf_insn_aux_data *aux_data = env->insn_aux_data;
	unsigned int orig_prog_len = env->prog->len;
	int err;

	if (bpf_rewrite_must_abort())
		return -EINTR;

	if (bpf_prog_is_offloaded(env->prog->aux))
		bpf_prog_offload_remove_insns(env, off, cnt);

	bpf_clear_insn_aux_data(env, off, cnt);

	err = bpf_remove_insns(env->prog, off, cnt);
	if (err)
		return err;

	/* before subprogs are adjusted, since it looks at them */
	bpf_adjust_func_ptrs_after_remove(env, off, cnt);

	err = adjust_subprog_starts_after_remove(env, off, cnt);
	if (err)
		return err;

	err = bpf_adj_linfo_after_remove(env, off, cnt);
	if (err)
		return err;

	adjust_insn_arrays_after_remove(env, off, cnt);

	memmove(aux_data + off,	aux_data + off + cnt,
		sizeof(*aux_data) * (orig_prog_len - off - cnt));
	env->insn_aux_data_len -= cnt;

	return 0;
}

static const struct bpf_insn NOP = BPF_JMP_IMM(BPF_JA, 0, 0, 0);
static const struct bpf_insn MAY_GOTO_0 = BPF_RAW_INSN(BPF_JMP | BPF_JCOND, 0, 0, 0, 0);

bool bpf_insn_is_cond_jump(u8 code)
{
	u8 op;

	op = BPF_OP(code);
	if (BPF_CLASS(code) == BPF_JMP32)
		return op != BPF_JA;

	if (BPF_CLASS(code) != BPF_JMP)
		return false;

	return op != BPF_JA && op != BPF_EXIT && op != BPF_CALL;
}

void bpf_opt_hard_wire_dead_code_branches(struct bpf_verifier_env *env)
{
	struct bpf_insn_aux_data *aux_data = env->insn_aux_data;
	struct bpf_insn ja = BPF_JMP_IMM(BPF_JA, 0, 0, 0);
	struct bpf_insn trap = BPF_JMP_IMM(BPF_JA, 0, 0, -1);
	struct bpf_insn *insn = env->prog->insnsi;
	const int insn_cnt = env->prog->len;
	int i;

	for (i = 0; i < insn_cnt; i++, insn++) {
		if (!bpf_insn_is_cond_jump(insn->code))
			continue;

		if (bpf_is_unwind_goto(insn) && aux_data[i + 1 + insn->off].seen) {
			/*
			 * The callee never exits. Its unwind_exit needs
			 * unwind_goto all the same, and the cpu predicts that it
			 * returns to what follows. Don't let the removal of dead
			 * code put something else there.
			 */
			if (!aux_data[i + 1].seen) {
				memcpy(insn + 1, &trap, sizeof(trap));
				aux_data[i + 1].seen = env->pass_cnt;
			}
			continue;
		}

		if (!aux_data[i + 1].seen)
			ja.off = insn->off;
		else if (!aux_data[i + 1 + insn->off].seen)
			ja.off = 0;
		else
			continue;

		if (bpf_prog_is_offloaded(env->prog->aux))
			bpf_prog_offload_replace_insn(env, i, &ja);

		memcpy(insn, &ja, sizeof(ja));
	}
}

/*
 * The address of a function might be taken by the code that is not dead,
 * while the function itself is dead code, since nothing calls it. Keep the first
 * instruction of such function, so that the address remains valid and differs
 * from the addresses of other functions. Make it a trap like
 * sanitize_dead_code() does.
 */
static void keep_funcs_with_addr_taken(struct bpf_verifier_env *env)
{
	struct bpf_insn_aux_data *aux_data = env->insn_aux_data;
	struct bpf_insn trap = BPF_JMP_IMM(BPF_JA, 0, 0, -1);
	struct bpf_insn *insn = env->prog->insnsi;
	int insn_cnt = env->prog->len;
	int i, t;

	for (i = 0; i < insn_cnt; i++) {
		if (!aux_data[i].seen || !bpf_pseudo_func(insn + i))
			continue;
		t = i + insn[i].imm + 1;
		if (aux_data[t].seen)
			continue;
		memcpy(insn + t, &trap, sizeof(trap));
		aux_data[t].zext_dst = false;
		aux_data[t].seen = env->pass_cnt;
	}
}

int bpf_opt_remove_dead_code(struct bpf_verifier_env *env)
{
	struct bpf_insn_aux_data *aux_data = env->insn_aux_data;
	int insn_cnt = env->prog->len;
	int i, err;

	keep_funcs_with_addr_taken(env);

	for (i = 0; i < insn_cnt; i++) {
		int j;

		j = 0;
		while (i + j < insn_cnt && !aux_data[i + j].seen)
			j++;
		if (!j)
			continue;

		err = verifier_remove_insns(env, i, j);
		if (err)
			return err;
		insn_cnt = env->prog->len;
	}

	return 0;
}

/* addr_space_cast of a pointer that is not in arena is a move, see is_cast_mov() */
void bpf_lower_cast_mov(struct bpf_verifier_env *env)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	struct bpf_insn *insn = env->prog->insnsi;
	int i;

	for (i = 0; i < env->prog->len; i++, insn++) {
		if (!aux[i].cast_mov)
			continue;
		if (insn->dst_reg == insn->src_reg)
			/* bpf_opt_remove_nops() removes it */
			*insn = NOP;
		else
			*insn = BPF_MOV64_REG(insn->dst_reg, insn->src_reg);
	}
}

/*
 * Make BPF_REG_ARENA_SP work. It holds the low 32 bits of the address, which is
 * what JITs add to the base of arena.
 *  - the main program takes a stack when it starts and returns it when it exits:
 *    the stack of the cpu when it's free, without a call.
 *    See struct bpf_arena_cpu_stack. So does a callback.
 *    bpf_throw() doesn't return it: the stack stays taken until the arena is freed.
 *  - a function that has a frame drops it before exit.
 *  - 'rX = r12' gives the address like user space sees it, as other addresses
 *    in arena are.
 * It's done after bpf_do_misc_fixups(), that takes a call for a call of a helper.
 */

#define CPU_STACK_OFF(field) offsetof(struct bpf_arena_cpu_stack, field)

/* reg = this_cpu_ptr(stacks) */
static struct bpf_insn *emit_arena_stack_percpu(struct bpf_verifier_env *env,
						struct bpf_insn *patch, int reg)
{
	struct bpf_insn ld_stacks[2] = {
		BPF_LD_IMM64(reg, (long)bpf_arena_stack_percpu(env->prog->aux->arena))
	};

	*patch++ = ld_stacks[0];
	*patch++ = ld_stacks[1];
	*patch++ = BPF_MOV64_PERCPU_REG(reg, reg);
	return patch;
}

/*
 * Take a stack at the start of the main program or of a callback.
 *
 *	cnt = busy++;
 *	if (!cnt)
 *		goto free;
 * slow:
 *	r12 = bpf_arena_stack_get(aux, cnt);
 *	if (r12)
 *		goto done;
 *	return 0;
 * free:
 *	if (size < what the program needs)
 *		goto slow;
 *	r12 = base;
 * done:
 *
 * r0 and r6-r9 are not initialized when a function starts. Neither are r2-r5 in
 * the main program. A callback has arguments there.
 */
static int insert_arena_stack_get(struct bpf_verifier_env *env, int s)
{
	struct bpf_insn ld_aux[2] = { BPF_LD_IMM64(BPF_REG_1, (long)env->prog->aux) };
	int local = bpf_jit_supports_local_atomics() ? BPF_ATOMIC_LOCAL : 0;
	int ptr = s ? BPF_REG_6 : BPF_REG_2, cnt = s ? BPF_REG_7 : BPF_REG_3;
	int size = s ? BPF_REG_8 : BPF_REG_4;
	struct bpf_subprog_info *sub = &env->subprog_info[s];
	struct bpf_insn *buf = env->insn_buf, *patch;
	int jfree, jdone, jslow, slow, free, done, i, spill = 0, start = sub->start;
	struct bpf_prog *new_prog;

	if (s) {
		spill = round_up(sub->stack_depth, BPF_REG_SIZE);
		sub->stack_depth = spill + MAX_BPF_FUNC_REG_ARGS * BPF_REG_SIZE;
		if (sub->stack_depth > env->stack_limit) {
			verbose(env, "no room in the stack of %s() for its arguments\n",
				bpf_subprog_name(env, s));
			return -EACCES;
		}
	}

	patch = emit_arena_stack_percpu(env, buf, ptr);
	*patch++ = BPF_MOV32_IMM(cnt, 1);
	*patch++ = BPF_ATOMIC_OP(BPF_DW, BPF_ADD | BPF_FETCH | local, ptr, cnt,
				 CPU_STACK_OFF(busy));
	jfree = patch++ - buf;
	slow = patch - buf;
	if (!s)
		*patch++ = BPF_MOV64_REG(BPF_REG_6, BPF_REG_1);
	for (i = BPF_REG_1; s && i <= BPF_REG_5; i++)
		*patch++ = BPF_STX_MEM(BPF_DW, BPF_REG_FP, i, -(spill + i * BPF_REG_SIZE));
	*patch++ = ld_aux[0];
	*patch++ = ld_aux[1];
	*patch++ = BPF_MOV64_REG(BPF_REG_2, cnt);
	*patch++ = BPF_EMIT_CALL(bpf_arena_stack_get);
	*patch++ = BPF_MOV32_REG(BPF_REG_ARENA_SP, BPF_REG_0);
	if (!s)
		*patch++ = BPF_MOV64_REG(BPF_REG_1, BPF_REG_6);
	for (i = BPF_REG_1; s && i <= BPF_REG_5; i++)
		*patch++ = BPF_LDX_MEM(BPF_DW, i, BPF_REG_FP, -(spill + i * BPF_REG_SIZE));
	jdone = patch++ - buf;
	*patch++ = BPF_MOV64_IMM(BPF_REG_0, 0);
	*patch++ = BPF_EXIT_INSN();
	free = patch - buf;
	*patch++ = BPF_LDX_MEM(BPF_W, size, ptr, CPU_STACK_OFF(size));
	jslow = patch++ - buf;
	*patch++ = BPF_LDX_MEM(BPF_W, BPF_REG_ARENA_SP, ptr, CPU_STACK_OFF(base));
	done = patch - buf;
	*patch++ = env->prog->insnsi[start];

	buf[jfree] = BPF_JMP_IMM(BPF_JEQ, cnt, 0, free - jfree - 1);
	buf[jdone] = BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, done - jdone - 1);
	/* size is 0 until the stack is allocated */
	buf[jslow] = BPF_JMP32_IMM(BPF_JLT, size, max(env->max_arena_stack_depth, 1),
				   slow - jslow - 1);

	new_prog = bpf_patch_insn_data(env, start, buf, patch - buf);
	if (!new_prog)
		return -ENOMEM;
	env->prog = new_prog;
	/* a jump to the first insn doesn't take the stack again */
	return adjust_jmp_off(env->prog, start, done);
}

int bpf_insert_arena_stack(struct bpf_verifier_env *env)
{
	struct bpf_map *arena = (struct bpf_map *)env->prog->aux->arena;
	struct bpf_subprog_info *subprogs = env->subprog_info;
	struct bpf_insn *insn_buf = env->insn_buf, *patch, *insn;
	struct bpf_prog_aux *aux = env->prog->aux;
	struct bpf_insn ld_aux[2] = { BPF_LD_IMM64(BPF_REG_1, (long)aux) };
	struct bpf_prog *new_prog;
	int i, cnt, cur = 0, err;

	if (!env->uses_arena_sp)
		return 0;

	/* the caller would get r12 of the callee back */
	for (i = 0; i < env->prog->len; i++) {
		insn = env->prog->insnsi + i;
		if (!bpf_pseudo_call(insn))
			continue;
		cur = bpf_find_subprog(env, i + insn->imm + 1);
		if (cur < 0 || !subprogs[cur].arena_stack_entry)
			continue;
		verbose(env, "%s() uses R%d and is both called and a callback\n",
			bpf_subprog_name(env, cur), BPF_REG_ARENA_SP);
		return -EINVAL;
	}
	cur = 0;

	/*
	 * With spare bytes r12 is neither the start nor the end of the stack,
	 * which may be at 0, so 'rX = r12' is not NULL.
	 */
	aux->arena_stack_size = round_up(env->max_arena_stack_depth + 64, PAGE_SIZE);

	for (i = 0; i < env->prog->len; i++) {
		insn = env->prog->insnsi + i;
		if (subprogs[cur + 1].start == i)
			cur++;
		patch = insn_buf;

		if (is_arena_sp_adj(insn)) {
			insn->code = BPF_ALU | BPF_ADD | BPF_K;
			env->insn_aux_data[i].zext_dst = true;
			continue;
		} else if (is_arena_sp_mov(insn)) {
			/* rX = addr_space_cast(r12, 0, 1) */
			if (!(arena->map_flags & BPF_F_NO_USER_CONV)) {
				insn->off = BPF_ADDR_SPACE_CAST;
				insn->imm = 1 << 16;
			}
			continue;
		} else if (insn->code == (BPF_JMP | BPF_EXIT)) {
			if (subprogs[cur].arena_stack_depth)
				*patch++ = BPF_ALU32_IMM(BPF_ADD, BPF_REG_ARENA_SP,
							 -(int)subprogs[cur].arena_stack_depth);
			if (!cur || subprogs[cur].arena_stack_entry) {
				/* r1-r5 are free */
				*patch++ = BPF_JMP32_IMM(BPF_JSET, BPF_REG_ARENA_SP,
							 BPF_ARENA_STACK_SLOW, 5);
				patch = emit_arena_stack_percpu(env, patch, BPF_REG_2);
				*patch++ = BPF_ST_MEM(BPF_DW, BPF_REG_2, CPU_STACK_OFF(busy), 0);
				*patch++ = *insn;
				*patch++ = BPF_MOV64_REG(BPF_REG_6, BPF_REG_0);
				*patch++ = ld_aux[0];
				*patch++ = ld_aux[1];
				*patch++ = BPF_MOV64_REG(BPF_REG_2, BPF_REG_ARENA_SP);
				*patch++ = BPF_EMIT_CALL(bpf_arena_stack_put);
				*patch++ = BPF_MOV64_REG(BPF_REG_0, BPF_REG_6);
			}
			if (patch == insn_buf)
				continue;
			*patch++ = *insn;
		} else {
			continue;
		}

		cnt = patch - insn_buf;
		new_prog = bpf_patch_insn_data(env, i, insn_buf, cnt);
		if (!new_prog)
			return -ENOMEM;
		env->prog = new_prog;
		i += cnt - 1;
	}

	/* From the last one, so that nothing moves in those that are yet to be done. */
	for (i = env->subprog_cnt - 1; i >= 0; i--) {
		if (i && !subprogs[i].arena_stack_entry)
			continue;
		err = insert_arena_stack_get(env, i);
		if (err)
			return err;
	}
	return 0;
}

int bpf_opt_remove_nops(struct bpf_verifier_env *env)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	struct bpf_insn *insn = env->prog->insnsi;
	int insn_cnt = env->prog->len;
	bool is_may_goto_0, is_ja;
	int i, err;

	for (i = 0; i < insn_cnt; i++) {
		is_may_goto_0 = !memcmp(&insn[i], &MAY_GOTO_0, sizeof(MAY_GOTO_0));
		is_ja = !memcmp(&insn[i], &NOP, sizeof(NOP));

		if (!is_may_goto_0 && !is_ja)
			continue;
		if (aux[i].indirect_target)
			continue;

		err = verifier_remove_insns(env, i, 1);
		if (err)
			return err;
		insn_cnt--;
		/* Go back one insn to catch may_goto +1; may_goto +0 sequence */
		i -= (is_may_goto_0 && i > 0) ? 2 : 1;
	}

	return 0;
}

int bpf_opt_subreg_zext_lo32_rnd_hi32(struct bpf_verifier_env *env,
					 const union bpf_attr *attr)
{
	struct bpf_insn *patch;
	/* use env->insn_buf as two independent buffers */
	struct bpf_insn *zext_patch = env->insn_buf;
	struct bpf_insn *rnd_hi32_patch = &env->insn_buf[2];
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	int i, patch_len, delta = 0, len = env->prog->len;
	struct bpf_insn *insns = env->prog->insnsi;
	struct bpf_prog *new_prog;
	bool rnd_hi32;

	rnd_hi32 = attr->prog_flags & BPF_F_TEST_RND_HI32;
	zext_patch[1] = BPF_ZEXT_REG(0);
	rnd_hi32_patch[1] = BPF_ALU64_IMM(BPF_MOV, BPF_REG_AX, 0);
	rnd_hi32_patch[2] = BPF_ALU64_IMM(BPF_LSH, BPF_REG_AX, 32);
	rnd_hi32_patch[3] = BPF_ALU64_REG(BPF_OR, 0, BPF_REG_AX);
	for (i = 0; i < len; i++) {
		int adj_idx = i + delta;
		struct bpf_insn insn;
		int load_reg;

		insn = insns[adj_idx];
		load_reg = insn_def_regno(&insn);
		if (!aux[adj_idx].zext_dst) {
			u8 code, class;
			u32 imm_rnd;

			if (!rnd_hi32)
				continue;

			code = insn.code;
			class = BPF_CLASS(code);
			if (load_reg == -1)
				continue;

			if (bpf_is_reg64(env->prog, &insn)) {
				if (class == BPF_LD &&
				    BPF_MODE(code) == BPF_IMM)
					i++;
				continue;
			}

			/* ctx load could be transformed into wider load. */
			if (class == BPF_LDX &&
			    aux[adj_idx].ptr_type == PTR_TO_CTX)
				continue;

			imm_rnd = get_random_u32();
			rnd_hi32_patch[0] = insn;
			rnd_hi32_patch[1].imm = imm_rnd;
			rnd_hi32_patch[3].dst_reg = load_reg;
			patch = rnd_hi32_patch;
			patch_len = 4;
			goto apply_patch_buffer;
		}

		/* Add in an zero-extend instruction if a) the JIT has requested
		 * it or b) it's a CMPXCHG.
		 *
		 * The latter is because: BPF_CMPXCHG always loads a value into
		 * R0, therefore always zero-extends. However some archs'
		 * equivalent instruction only does this load when the
		 * comparison is successful. This detail of CMPXCHG is
		 * orthogonal to the general zero-extension behaviour of the
		 * CPU, so it's treated independently of bpf_jit_needs_zext.
		 */
		if (!bpf_jit_needs_zext() && !is_cmpxchg_insn(&insn))
			continue;

		/* Zero-extension is done by the caller. */
		if (bpf_pseudo_kfunc_call(&insn))
			continue;

		if (verifier_bug_if(load_reg == -1, env,
				    "zext_dst is set, but no reg is defined"))
			return -EFAULT;

		zext_patch[0] = insn;
		zext_patch[1].dst_reg = load_reg;
		zext_patch[1].src_reg = load_reg;
		patch = zext_patch;
		patch_len = 2;
apply_patch_buffer:
		new_prog = bpf_patch_insn_data(env, adj_idx, patch, patch_len);
		if (!new_prog)
			return -ENOMEM;
		env->prog = new_prog;
		insns = new_prog->insnsi;
		aux = env->insn_aux_data;
		delta += patch_len - 1;
	}

	return 0;
}

/*
 * The prologue takes the context from R1, and it can clobber R2-R5. An
 * extension gets the arguments of the function that it replaces.
 */
static bool ext_prog_takes_prologue(const struct bpf_verifier_env *env)
{
	const struct bpf_subprog_info *sub = &env->subprog_info[0];
	int i, cnt = min_t(int, sub->arg_slot_cnt, MAX_BPF_FUNC_REG_ARGS);

	if (!cnt || sub->args[0].arg_type != ARG_PTR_TO_CTX)
		return false;

	for (i = 1; i < cnt; i++)
		if (sub->args[i].arg_type != ARG_SCALAR)
			return false;

	return true;
}

/* convert load instructions that access fields of a context type into a
 * sequence of instructions that access fields of the underlying structure:
 *     struct __sk_buff    -> struct sk_buff
 *     struct bpf_sock_ops -> struct sock
 */
/*
 * A load through an __arena pointer member of a kernel struct reads the kernel
 * address of arena memory. Append the conversion to the arena pointer form,
 * (u32)(kaddr - kern_vm_start), that the struct_ops trampoline applies to
 * __arena arguments. A __nullable member keeps NULL as NULL, tested on the
 * full kernel address, and so does a probed load, which reads as 0 when it
 * faults. Returns the number of insns in @buf, 0 when the insn loads no such
 * member, or an error when it does so on some paths only.
 */
static int arena_member_fixup(struct bpf_verifier_env *env, int idx, struct bpf_insn *insn,
			      struct bpf_insn *buf)
{
	struct bpf_insn_aux_data *aux = &env->insn_aux_data[idx];
	int cnt = 0;
	u32 base;

	if (!aux->arena_member)
		return 0;
	if (aux->non_arena_load) {
		verbose(env, "an insn loads an arena pointer member on one path and something else on another\n");
		return -EINVAL;
	}

	base = bpf_arena_get_kern_vm_start(env->prog->aux->arena);
	buf[cnt++] = *insn;
	if (aux->arena_member_nullable || BPF_MODE(insn->code) == BPF_PROBE_MEM)
		buf[cnt++] = BPF_JMP_IMM(BPF_JEQ, insn->dst_reg, 0, 1);
	buf[cnt++] = BPF_ALU32_IMM(BPF_SUB, insn->dst_reg, (s32)base);
	return cnt;
}

int bpf_convert_ctx_accesses(struct bpf_verifier_env *env)
{
	struct bpf_subprog_info *subprogs = env->subprog_info;
	const struct bpf_verifier_ops *ops = env->ops;
	int i, cnt, size, ctx_field_size, ret, delta = 0, epilogue_cnt = 0;
	const int insn_cnt = env->prog->len;
	struct bpf_insn *epilogue_buf = env->epilogue_buf;
	struct bpf_insn *insn_buf = env->insn_buf;
	struct bpf_insn *insn;
	u32 target_size, size_default, off;
	struct bpf_prog *new_prog;
	enum bpf_access_type type;
	bool is_narrower_load;
	int epilogue_idx = 0;

	if (ops->gen_epilogue) {
		epilogue_cnt = ops->gen_epilogue(epilogue_buf, env->prog,
						 -(subprogs[0].stack_depth + 8));
		if (epilogue_cnt >= INSN_BUF_SIZE) {
			verifier_bug(env, "epilogue is too long");
			return -EFAULT;
		} else if (epilogue_cnt) {
			/* Save the ARG_PTR_TO_CTX for the epilogue to use */
			cnt = 0;
			subprogs[0].stack_depth += 8;
			insn_buf[cnt++] = BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_1,
						      -subprogs[0].stack_depth);
			insn_buf[cnt++] = env->prog->insnsi[0];
			new_prog = __bpf_patch_insn_data(env, 0, insn_buf, cnt,
							 BPF_PATCH_MOVE_TARGET);
			if (!new_prog)
				return -ENOMEM;
			env->prog = new_prog;
			delta += cnt - 1;

			ret = add_kfunc_in_insns(env, epilogue_buf, epilogue_cnt - 1);
			if (ret < 0)
				return ret;
		}
	}

	if (ops->gen_prologue || env->seen_direct_write) {
		if (!ops->gen_prologue) {
			verifier_bug(env, "gen_prologue is null");
			return -EFAULT;
		}
		cnt = ops->gen_prologue(insn_buf, env->seen_direct_write,
					env->prog);
		if (cnt >= INSN_BUF_SIZE) {
			verifier_bug(env, "prologue is too long");
			return -EFAULT;
		} else if (cnt) {
			if (env->prog->type == BPF_PROG_TYPE_EXT &&
			    !ext_prog_takes_prologue(env)) {
				verbose(env,
					"Extension writing packet data must take ctx and scalars only\n");
				return -EINVAL;
			}
			if (env->prog->type == BPF_PROG_TYPE_EXT &&
			    bpf_check_ext_prologue(&env->log,
						   env->prog->aux->dst_prog,
						   env->prog->aux->attach_btf_id))
				return -EINVAL;
			env->prog->aux->has_prologue = true;
			new_prog = __bpf_patch_insn_data(env, 0, insn_buf, cnt,
							 BPF_PATCH_MOVE_TARGET);
			if (!new_prog)
				return -ENOMEM;

			env->prog = new_prog;
			delta += cnt - 1;

			ret = add_kfunc_in_insns(env, insn_buf, cnt - 1);
			if (ret < 0)
				return ret;
		}
	}

	if (delta)
		WARN_ON(adjust_jmp_off(env->prog, 0, delta));

	if (bpf_prog_is_offloaded(env->prog->aux))
		return 0;

	insn = env->prog->insnsi + delta;

	for (i = 0; i < insn_cnt; i++, insn++) {
		bpf_convert_ctx_access_t convert_ctx_access;
		enum bpf_reg_type ptr_type;
		u8 mode;

		if (env->insn_aux_data[i + delta].nospec) {
			WARN_ON_ONCE(env->insn_aux_data[i + delta].alu_state);
			struct bpf_insn *patch = insn_buf;

			*patch++ = BPF_ST_NOSPEC();
			*patch = *insn;
			ret = bpf_adj_moved_insn(patch++, 1);
			if (ret) {
				verbose(env, "insn %d cannot be patched due to 16-bit range\n",
					env->insn_aux_data[i + delta].orig_idx);
				return ret;
			}
			cnt = patch - insn_buf;
			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta    += cnt - 1;
			env->prog = new_prog;
			insn      = new_prog->insnsi + i + delta;
			/* This can not be easily merged with the
			 * nospec_result-case, because an insn may require a
			 * nospec before and after itself. Therefore also do not
			 * 'continue' here but potentially apply further
			 * patching to insn. *insn should equal patch[1] now.
			 */
		}

		if (insn->code == (BPF_LDX | BPF_MEM | BPF_B) ||
		    insn->code == (BPF_LDX | BPF_MEM | BPF_H) ||
		    insn->code == (BPF_LDX | BPF_MEM | BPF_W) ||
		    insn->code == (BPF_LDX | BPF_MEM | BPF_DW) ||
		    insn->code == (BPF_LDX | BPF_MEMSX | BPF_B) ||
		    insn->code == (BPF_LDX | BPF_MEMSX | BPF_H) ||
		    insn->code == (BPF_LDX | BPF_MEMSX | BPF_W)) {
			type = BPF_READ;
		} else if (insn->code == (BPF_STX | BPF_MEM | BPF_B) ||
			   insn->code == (BPF_STX | BPF_MEM | BPF_H) ||
			   insn->code == (BPF_STX | BPF_MEM | BPF_W) ||
			   insn->code == (BPF_STX | BPF_MEM | BPF_DW) ||
			   insn->code == (BPF_ST | BPF_MEM | BPF_B) ||
			   insn->code == (BPF_ST | BPF_MEM | BPF_H) ||
			   insn->code == (BPF_ST | BPF_MEM | BPF_W) ||
			   insn->code == (BPF_ST | BPF_MEM | BPF_DW)) {
			type = BPF_WRITE;
		} else if ((insn->code == (BPF_STX | BPF_ATOMIC | BPF_B) ||
			    insn->code == (BPF_STX | BPF_ATOMIC | BPF_H) ||
			    insn->code == (BPF_STX | BPF_ATOMIC | BPF_W) ||
			    insn->code == (BPF_STX | BPF_ATOMIC | BPF_DW)) &&
			   env->insn_aux_data[i + delta].ptr_type == PTR_TO_ARENA) {
			insn->code = BPF_STX | BPF_PROBE_ATOMIC | BPF_SIZE(insn->code);
			env->prog->aux->num_exentries++;
			continue;
		} else if (insn->code == (BPF_STX | BPF_ATOMIC | BPF_DW) &&
			   insn->imm == BPF_LOAD_ACQ &&
			   env->insn_aux_data[i + delta].arena_member) {
			/* an acquire load of an __arena member is rewritten like a plain load */
			cnt = arena_member_fixup(env, i + delta, insn, insn_buf);
			if (cnt < 0)
				return cnt;
			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta    += cnt - 1;
			env->prog = new_prog;
			insn      = new_prog->insnsi + i + delta;
			continue;
		} else if (insn->code == (BPF_JMP | BPF_EXIT) &&
			   epilogue_cnt &&
			   i + delta < subprogs[1].start) {
			/* Generate epilogue for the main prog */
			if (epilogue_idx) {
				/* jump back to the earlier generated epilogue */
				insn_buf[0] = BPF_JMP32_A(epilogue_idx - i - delta - 1);
				cnt = 1;
			} else {
				memcpy(insn_buf, epilogue_buf,
				       epilogue_cnt * sizeof(*epilogue_buf));
				cnt = epilogue_cnt;
				/* epilogue_idx cannot be 0. It must have at
				 * least one ctx ptr saving insn before the
				 * epilogue.
				 */
				epilogue_idx = i + delta;
			}
			goto patch_insn_buf;
		} else {
			continue;
		}

		if (type == BPF_WRITE &&
		    env->insn_aux_data[i + delta].nospec_result) {
			/* nospec_result is only used to mitigate Spectre v4 and
			 * to limit verification-time for Spectre v1.
			 */
			struct bpf_insn *patch = insn_buf;

			*patch++ = *insn;
			*patch++ = BPF_ST_NOSPEC();
			cnt = patch - insn_buf;
			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta    += cnt - 1;
			env->prog = new_prog;
			insn      = new_prog->insnsi + i + delta;
			continue;
		}

		ptr_type = env->insn_aux_data[i + delta].ptr_type;
		switch ((int)ptr_type) {
		case PTR_TO_CTX:
			if (!ops->convert_ctx_access)
				continue;
			convert_ctx_access = ops->convert_ctx_access;
			break;
		case PTR_TO_SOCKET:
		case PTR_TO_SOCK_COMMON:
			convert_ctx_access = bpf_sock_convert_ctx_access;
			break;
		case PTR_TO_TCP_SOCK:
			convert_ctx_access = bpf_tcp_sock_convert_ctx_access;
			break;
		case PTR_TO_XDP_SOCK:
			convert_ctx_access = bpf_xdp_sock_convert_ctx_access;
			break;
		case PTR_TO_ARENA:
			if (BPF_MODE(insn->code) == BPF_MEMSX) {
				if (!bpf_jit_supports_insn(insn, true)) {
					verbose(env, "sign extending loads from arena are not supported yet\n");
					return -EOPNOTSUPP;
				}
				insn->code = BPF_CLASS(insn->code) | BPF_PROBE_MEM32SX | BPF_SIZE(insn->code);
			} else {
				insn->code = BPF_CLASS(insn->code) | BPF_PROBE_MEM32 | BPF_SIZE(insn->code);
			}
			env->prog->aux->num_exentries++;
			continue;
		default:
			/*
			 * A pointer which may fault on a dereference must not
			 * be loaded from without fault protection, hence turn
			 * the BPF_LDX into a BPF_PROBE_MEM one so that a bad
			 * address is handled rather than panicking the kernel.
			 * A store through one is rejected earlier, there is no
			 * probed counterpart to rewrite it into.
			 */
			if (bpf_is_ptr_to_mem_or_btf_id(ptr_type) &&
			    bpf_may_fault_on_deref(ptr_type) &&
			    type == BPF_READ) {
				if (BPF_MODE(insn->code) == BPF_MEM)
					insn->code = BPF_LDX | BPF_PROBE_MEM |
						     BPF_SIZE(insn->code);
				else
					insn->code = BPF_LDX | BPF_PROBE_MEMSX |
						     BPF_SIZE(insn->code);
				env->prog->aux->num_exentries++;
			} else if (verifier_bug_if(bpf_may_fault_on_deref(ptr_type), env,
						   "access to a fault prone pointer is not rewritten as a probed one")) {
				return -EFAULT;
			}

			cnt = arena_member_fixup(env, i + delta, insn, insn_buf);
			if (cnt < 0)
				return cnt;
			if (!cnt)
				continue;
			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta    += cnt - 1;
			env->prog = new_prog;
			insn      = new_prog->insnsi + i + delta;
			continue;
		}

		ctx_field_size = env->insn_aux_data[i + delta].ctx_field_size;
		size = BPF_LDST_BYTES(insn);
		mode = BPF_MODE(insn->code);

		/* If the read access is a narrower load of the field,
		 * convert to a 4/8-byte load, to minimum program type specific
		 * convert_ctx_access changes. If conversion is successful,
		 * we will apply proper mask to the result.
		 */
		is_narrower_load = size < ctx_field_size;
		size_default = bpf_ctx_off_adjust_machine(ctx_field_size);
		off = insn->off;
		if (is_narrower_load) {
			u8 size_code;

			if (type == BPF_WRITE) {
				verifier_bug(env, "narrow ctx access misconfigured");
				return -EFAULT;
			}

			size_code = BPF_H;
			if (ctx_field_size == 4)
				size_code = BPF_W;
			else if (ctx_field_size == 8)
				size_code = BPF_DW;

			insn->off = off & ~(size_default - 1);
			insn->code = BPF_LDX | BPF_MEM | size_code;
		}

		target_size = 0;
		cnt = convert_ctx_access(type, insn, insn_buf, env->prog,
					 &target_size);
		if (cnt == 0 || cnt >= INSN_BUF_SIZE ||
		    (ctx_field_size && !target_size)) {
			verifier_bug(env, "error during ctx access conversion (%d)", cnt);
			return -EFAULT;
		}

		if (is_narrower_load && size < target_size) {
			u8 shift = bpf_ctx_narrow_access_offset(
				off, size, size_default) * 8;
			if (shift && cnt + 1 >= INSN_BUF_SIZE) {
				verifier_bug(env, "narrow ctx load misconfigured");
				return -EFAULT;
			}
			if (ctx_field_size <= 4) {
				if (shift)
					insn_buf[cnt++] = BPF_ALU32_IMM(BPF_RSH,
									insn->dst_reg,
									shift);
				insn_buf[cnt++] = BPF_ALU32_IMM(BPF_AND, insn->dst_reg,
								(1 << size * 8) - 1);
			} else {
				if (shift)
					insn_buf[cnt++] = BPF_ALU64_IMM(BPF_RSH,
									insn->dst_reg,
									shift);
				insn_buf[cnt++] = BPF_ALU32_IMM(BPF_AND, insn->dst_reg,
								(1ULL << size * 8) - 1);
			}
		}
		if (mode == BPF_MEMSX)
			insn_buf[cnt++] = BPF_RAW_INSN(BPF_ALU64 | BPF_MOV | BPF_X,
						       insn->dst_reg, insn->dst_reg,
						       size * 8, 0);

patch_insn_buf:
		new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
		if (!new_prog)
			return -ENOMEM;

		delta += cnt - 1;

		/* keep walking new program and skip insns we just inserted */
		env->prog = new_prog;
		insn      = new_prog->insnsi + i + delta;
	}

	return 0;
}

static u32 *bpf_dup_subprog_starts(struct bpf_verifier_env *env)
{
	u32 *starts = NULL;

	starts = kvmalloc_objs(u32, env->subprog_cnt, GFP_KERNEL_ACCOUNT);
	if (starts) {
		for (int i = 0; i < env->subprog_cnt; i++)
			starts[i] = env->subprog_info[i].start;
	}
	return starts;
}

static void bpf_restore_subprog_starts(struct bpf_verifier_env *env, u32 *orig_starts)
{
	for (int i = 0; i < env->subprog_cnt; i++)
		env->subprog_info[i].start = orig_starts[i];
	/* restore the start of fake 'exit' subprog as well */
	env->subprog_info[env->subprog_cnt].start = env->prog->len;
}

/*
 * Replace the offsets of functions with their addresses in the maps of
 * the program, see resolve_func_ptrs() in verifier.c. The program must be
 * the only user of such map. From now on no other program can use it, see
 * bpf_map_claim().
 */
static int resolve_func_ptrs(struct bpf_verifier_env *env, struct bpf_prog *prog,
			     struct bpf_prog **func)
{
	unsigned long me = (unsigned long)prog->aux;
	struct bpf_func_ptr *ptr;
	int i, err, subprog;
	u64 addr, new, *slot;

	for (i = 0; i < env->func_ptr_cnt; i++) {
		ptr = &env->func_ptrs[i];

		/* pointers are sorted by map */
		if ((!i || ptr->map != ptr[-1].map) &&
		    cmpxchg(&ptr->map->user, me, me | BPF_MAP_USER_PATCHED) != me) {
			verbose(env, "map '%s' is used by another program\n", ptr->map->name);
			return -EBUSY;
		}

		/* it's the address of the value of the map whatever the offset is */
		err = ptr->map->ops->map_direct_value_addr(ptr->map, &addr, 0);
		if (verifier_bug_if(err, env, "no value of map '%s'", ptr->map->name))
			return -EFAULT;
		slot = (u64 *)(unsigned long)(addr + ptr->map_off);

		/*
		 * The function that is dead code is removed and the pointer is
		 * NULL. The program may read it, but callx of it is dead code
		 * too, see check_func_callx().
		 */
		new = 0;
		if (ptr->xlated_off != BPF_FUNC_PTR_DELETED) {
			subprog = bpf_find_subprog(env, ptr->xlated_off);
			if (verifier_bug_if(!func || subprog <= 0, env, "no function at insn %u",
					    ptr->xlated_off))
				return -EFAULT;
			new = (unsigned long)func[subprog]->bpf_func;
		}

		/* the map is frozen and nothing else uses it */
		if (verifier_bug_if(*slot != (u64)ptr->orig_off * sizeof(struct bpf_insn), env,
				    "map '%s' offset %u changed", ptr->map->name, ptr->map_off))
			return -EFAULT;
		WRITE_ONCE(*slot, new);
	}
	return 0;
}

static int jit_subprogs(struct bpf_verifier_env *env)
{
	struct bpf_prog *prog = env->prog, **func, *tmp;
	int i, j, subprog_start, subprog_end = 0, len, subprog;
	struct bpf_map *map_ptr;
	struct bpf_insn *insn;
	void *old_bpf_func;
	int err, num_exentries;

	for (i = 0, insn = prog->insnsi; i < prog->len; i++, insn++) {
		if (!bpf_pseudo_func(insn) && !bpf_pseudo_call(insn))
			continue;

		/* Upon error here we cannot fall back to interpreter but
		 * need a hard reject of the program. Thus -EFAULT is
		 * propagated in any case.
		 */
		subprog = bpf_find_subprog(env, i + insn->imm + 1);
		if (verifier_bug_if(subprog < 0, env, "No program to jit at insn %d",
				    i + insn->imm + 1))
			return -EFAULT;
		/* temporarily remember subprog id inside insn instead of
		 * aux_data, since next loop will split up all insns into funcs
		 */
		insn->off = subprog;
		/* remember original imm in case JIT fails and fallback
		 * to interpreter will be needed
		 */
		env->insn_aux_data[i].call_imm = insn->imm;
		/* point imm to __bpf_call_base+1 from JITs point of view */
		insn->imm = 1;
		if (bpf_pseudo_func(insn)) {
#if defined(MODULES_VADDR)
			u64 addr = MODULES_VADDR;
#else
			u64 addr = VMALLOC_START;
#endif
			/* jit (e.g. x86_64) may emit fewer instructions
			 * if it learns a u32 imm is the same as a u64 imm.
			 * Set close enough to possible prog address.
			 */
			insn[0].imm = (u32)addr;
			insn[1].imm = addr >> 32;
		}
	}

	err = bpf_prog_alloc_jited_linfo(prog);
	if (err)
		goto out_undo_insn;

	err = -ENOMEM;
	func = kzalloc_objs(prog, env->subprog_cnt);
	if (!func)
		goto out_undo_insn;

	for (i = 0; i < env->subprog_cnt; i++) {
		subprog_start = subprog_end;
		subprog_end = env->subprog_info[i + 1].start;

		len = subprog_end - subprog_start;
		/* bpf_prog_run() doesn't call subprogs directly,
		 * hence main prog stats include the runtime of subprogs.
		 * subprogs don't have IDs and not reachable via prog_get_next_id
		 * func[i]->stats will never be accessed and stays NULL
		 */
		func[i] = bpf_prog_alloc_no_stats(bpf_prog_size(len), GFP_USER);
		if (!func[i])
			goto out_free;
		memcpy(func[i]->insnsi, &prog->insnsi[subprog_start],
		       len * sizeof(struct bpf_insn));
		func[i]->type = prog->type;
		func[i]->len = len;
		if (bpf_prog_calc_tag(func[i]))
			goto out_free;
		func[i]->is_func = 1;
		func[i]->sleepable = prog->sleepable;
		func[i]->blinded = prog->blinded;
		func[i]->aux->func_idx = i;
		/* Below members will be freed only at prog->aux */
		func[i]->aux->btf = prog->aux->btf;
		func[i]->aux->subprog_start = subprog_start;
		func[i]->aux->func_info = prog->aux->func_info;
		func[i]->aux->func_info_cnt = prog->aux->func_info_cnt;
		func[i]->aux->poke_tab = prog->aux->poke_tab;
		func[i]->aux->size_poke_tab = prog->aux->size_poke_tab;
		func[i]->aux->main_prog_aux = prog->aux;

		for (j = 0; j < prog->aux->size_poke_tab; j++) {
			struct bpf_jit_poke_descriptor *poke;

			poke = &prog->aux->poke_tab[j];
			if (poke->insn_idx < subprog_end &&
			    poke->insn_idx >= subprog_start)
				poke->aux = func[i]->aux;
		}

		func[i]->aux->name[0] = 'F';
		func[i]->aux->stack_depth = env->subprog_info[i].stack_depth;
		if (env->subprog_info[i].priv_stack_mode == PRIV_STACK_ADAPTIVE)
			func[i]->aux->jits_use_priv_stack = true;

		func[i]->jit_requested = 1;
		func[i]->blinding_requested = prog->blinding_requested;
		func[i]->aux->kfunc_tab = prog->aux->kfunc_tab;
		func[i]->aux->kfunc_btf_tab = prog->aux->kfunc_btf_tab;
		func[i]->aux->linfo = prog->aux->linfo;
		func[i]->aux->nr_linfo = prog->aux->nr_linfo;
		func[i]->aux->jited_linfo = prog->aux->jited_linfo;
		func[i]->aux->linfo_idx = env->subprog_info[i].linfo_idx;
		func[i]->aux->arena = prog->aux->arena;
		func[i]->aux->arena_stack_size = prog->aux->arena_stack_size;
		func[i]->aux->arena_stack_entry = env->subprog_info[i].arena_stack_entry;
		func[i]->aux->uses_arena_insns = bpf_prog_has_arena_insns(func[i]);
		func[i]->aux->used_maps = env->used_maps;
		func[i]->aux->used_map_cnt = env->used_map_cnt;
		num_exentries = 0;
		insn = func[i]->insnsi;
		for (j = 0; j < func[i]->len; j++, insn++) {
			if (BPF_CLASS(insn->code) == BPF_LDX &&
			    (BPF_MODE(insn->code) == BPF_PROBE_MEM ||
			     BPF_MODE(insn->code) == BPF_PROBE_MEM32 ||
			     BPF_MODE(insn->code) == BPF_PROBE_MEM32SX ||
			     BPF_MODE(insn->code) == BPF_PROBE_MEMSX))
				num_exentries++;
			if ((BPF_CLASS(insn->code) == BPF_STX ||
			     BPF_CLASS(insn->code) == BPF_ST) &&
			     BPF_MODE(insn->code) == BPF_PROBE_MEM32)
				num_exentries++;
			if (BPF_CLASS(insn->code) == BPF_STX &&
			     BPF_MODE(insn->code) == BPF_PROBE_ATOMIC)
				num_exentries++;
			if (bpf_is_unwind_goto(insn))
				num_exentries++;
		}
		func[i]->aux->num_exentries = num_exentries;
		func[i]->aux->tail_call_reachable = env->subprog_info[i].tail_call_reachable;
		func[i]->aux->exception_cb = env->subprog_info[i].is_exception_cb;
		func[i]->aux->changes_pkt_data = env->subprog_info[i].changes_pkt_data;
		func[i]->aux->might_sleep = env->subprog_info[i].might_sleep;
		func[i]->aux->can_unwind = env->subprog_info[i].can_unwind;
		func[i]->aux->recursive = env->subprog_info[i].recursion_weight;
		func[i]->aux->token = prog->aux->token;
		if (!i)
			func[i]->aux->exception_boundary = env->seen_exception;
		func[i] = bpf_int_jit_compile(env, func[i]);
		if (!func[i]->jited) {
			err = -ENOTSUPP;
			goto out_free;
		}
		cond_resched();
	}

	/* at this point all bpf functions were successfully JITed
	 * now populate all bpf_calls with correct addresses and
	 * run last pass of JIT
	 */
	for (i = 0; i < env->subprog_cnt; i++) {
		insn = func[i]->insnsi;
		for (j = 0; j < func[i]->len; j++, insn++) {
			if (bpf_pseudo_func(insn)) {
				subprog = insn->off;
				insn[0].imm = (u32)(long)func[subprog]->bpf_func;
				insn[1].imm = ((u64)(long)func[subprog]->bpf_func) >> 32;
				continue;
			}
			if (!bpf_pseudo_call(insn))
				continue;
			subprog = insn->off;
			insn->imm = BPF_CALL_IMM(func[subprog]->bpf_func);
		}

		/* we use the aux data to keep a list of the start addresses
		 * of the JITed images for each function in the program
		 *
		 * for some architectures, such as powerpc64, the imm field
		 * might not be large enough to hold the offset of the start
		 * address of the callee's JITed image from __bpf_call_base
		 *
		 * in such cases, we can lookup the start address of a callee
		 * by using its subprog id, available from the off field of
		 * the call instruction, as an index for this list
		 */
		func[i]->aux->func = func;
		func[i]->aux->func_cnt = env->subprog_cnt - env->hidden_subprog_cnt;
		func[i]->aux->real_func_cnt = env->subprog_cnt;
	}
	for (i = 0; i < env->subprog_cnt; i++) {
		old_bpf_func = func[i]->bpf_func;
		tmp = bpf_int_jit_compile(env, func[i]);
		if (tmp != func[i] || func[i]->bpf_func != old_bpf_func) {
			verbose(env, "JIT doesn't support bpf-to-bpf calls\n");
			err = -ENOTSUPP;
			goto out_free;
		}
		cond_resched();
	}

	/* the addresses of all functions are final */
	err = resolve_func_ptrs(env, prog, func);
	if (err)
		goto out_free;

	/*
	 * Cleanup func[i]->aux fields which aren't required
	 * or can become invalid in future
	 */
	for (i = 0; i < env->subprog_cnt; i++) {
		func[i]->aux->used_maps = NULL;
		func[i]->aux->used_map_cnt = 0;
	}

	/* finally lock prog and jit images for all functions and
	 * populate kallsysm. Begin at the first subprogram, since
	 * bpf_prog_load will add the kallsyms for the main program.
	 */
	for (i = 1; i < env->subprog_cnt; i++) {
		err = bpf_prog_lock_ro(func[i]);
		if (err)
			goto out_free;
	}

	for (i = 1; i < env->subprog_cnt; i++)
		bpf_prog_kallsyms_add(func[i]);

	/* Last step: make now unused interpreter insns from main
	 * prog consistent for later dump requests, so they can
	 * later look the same as if they were interpreted only.
	 */
	for (i = 0, insn = prog->insnsi; i < prog->len; i++, insn++) {
		if (bpf_pseudo_func(insn)) {
			insn[0].imm = env->insn_aux_data[i].call_imm;
			insn[1].imm = insn->off;
			insn->off = 0;
			continue;
		}
		if (!bpf_pseudo_call(insn))
			continue;
		insn->imm = env->insn_aux_data[i].call_imm;
		subprog = bpf_find_subprog(env, i + insn->imm + 1);
		insn->off = subprog;
	}

	prog->jited = 1;
	prog->bpf_func = func[0]->bpf_func;
	prog->jited_len = func[0]->jited_len;
	prog->aux->extable = func[0]->aux->extable;
	prog->aux->num_exentries = func[0]->aux->num_exentries;
	prog->aux->func = func;
	prog->aux->func_cnt = env->subprog_cnt - env->hidden_subprog_cnt;
	prog->aux->real_func_cnt = env->subprog_cnt;
	prog->aux->bpf_exception_cb = (void *)func[env->exception_callback_subprog]->bpf_func;
	prog->aux->exception_boundary = func[0]->aux->exception_boundary;
	prog->aux->stack_arg_sp_adjust = func[0]->aux->stack_arg_sp_adjust;
	bpf_prog_jit_attempt_done(prog);
	return 0;
out_free:
	/* We failed JIT'ing, so at this point we need to unregister poke
	 * descriptors from subprogs, so that kernel is not attempting to
	 * patch it anymore as we're freeing the subprog JIT memory.
	 */
	for (i = 0; i < prog->aux->size_poke_tab; i++) {
		map_ptr = prog->aux->poke_tab[i].tail_call.map;
		map_ptr->ops->map_poke_untrack(map_ptr, prog->aux);
	}
	/* At this point we're guaranteed that poke descriptors are not
	 * live anymore. We can just unlink its descriptor table as it's
	 * released with the main prog.
	 */
	for (i = 0; i < env->subprog_cnt; i++) {
		if (!func[i])
			continue;
		func[i]->aux->poke_tab = NULL;
		bpf_jit_free(func[i]);
	}
	kfree(func);
out_undo_insn:
	bpf_prog_jit_attempt_done(prog);
	return err;
}

int bpf_jit_subprogs(struct bpf_verifier_env *env)
{
	int err, i;
	bool blinded = false;
	struct bpf_insn *insn;
	struct bpf_prog *prog, *orig_prog;
	u32 *orig_subprog_starts;

	/* all functions that the maps point to are removed as dead code */
	if (env->subprog_cnt <= 1)
		return resolve_func_ptrs(env, env->prog, NULL);

	prog = orig_prog = env->prog;
	if (bpf_prog_need_blind(prog)) {
		orig_subprog_starts = bpf_dup_subprog_starts(env);
		if (!orig_subprog_starts) {
			err = -ENOMEM;
			goto out_cleanup;
		}
		prog = bpf_jit_blind_constants(env, prog);
		if (IS_ERR(prog)) {
			err = PTR_ERR(prog);
			prog = orig_prog;
			goto out_restore;
		}
		blinded = true;
	}

	err = jit_subprogs(env);
	if (err)
		goto out_jit_err;

	if (blinded) {
		bpf_jit_prog_release_other(prog, orig_prog);
		kvfree(orig_subprog_starts);
	}

	return 0;

out_jit_err:
	if (blinded) {
		bpf_jit_prog_release_other(orig_prog, prog);
		/* roll back to the clean original prog */
		prog = env->prog = orig_prog;
		goto out_restore;
	} else {
		if (err != -EFAULT) {
			/*
			 * We will fall back to interpreter mode when err is not -EFAULT, before
			 * that, insn->off and insn->imm should be restored to their original
			 * values since they were modified by jit_subprogs.
			 */
			for (i = 0, insn = prog->insnsi; i < prog->len; i++, insn++) {
				if (!bpf_pseudo_call(insn))
					continue;
				insn->off = 0;
				insn->imm = env->insn_aux_data[i].call_imm;
			}
		}
		goto out_cleanup;
	}

out_restore:
	bpf_restore_subprog_starts(env, orig_subprog_starts);
	kvfree(orig_subprog_starts);
out_cleanup:
	/* cleanup main prog to be interpreted */
	prog->jit_requested = 0;
	prog->blinding_requested = 0;
	return err;
}

int bpf_fixup_call_args(struct bpf_verifier_env *env)
{
#ifndef CONFIG_BPF_JIT_ALWAYS_ON
	struct bpf_prog *prog = env->prog;
	struct bpf_insn *insn = prog->insnsi;
	int depth;
#endif
	int i, err = 0;

	for (i = 0; i < env->subprog_cnt; i++) {
		struct bpf_subprog_info *subprog = &env->subprog_info[i];
		u16 outgoing = subprog->stack_arg_cnt - bpf_in_stack_arg_cnt(subprog);

		if (subprog->max_out_stack_arg_cnt > outgoing) {
			verbose(env,
				"func#%d writes %u stack arg slots, but calls only require %u\n",
				i, subprog->max_out_stack_arg_cnt, outgoing);
			return -EINVAL;
		}
	}

	if (env->prog->jit_requested &&
	    !bpf_prog_is_offloaded(env->prog->aux)) {
		err = bpf_jit_subprogs(env);
		if (err == 0)
			return 0;
		if (err == -EFAULT || err == -EINTR)
			return err;
	}
#ifndef CONFIG_BPF_JIT_ALWAYS_ON
	if (prog->jit_required) {
		verbose(env, "program requires BPF JIT compiler but it is not available\n");
		return -EINVAL;
	}
	for (i = 0; i < env->subprog_cnt; i++) {
		if (bpf_in_stack_arg_cnt(&env->subprog_info[i])) {
			verbose(env, "stack args are not supported in non-JITed programs\n");
			return -EINVAL;
		}
	}
	if (env->subprog_cnt > 1 && env->prog->aux->tail_call_reachable) {
		/* When JIT fails the progs with bpf2bpf calls and tail_calls
		 * have to be rejected, since interpreter doesn't support them yet.
		 */
		verbose(env, "tail_calls are not allowed in non-JITed programs with bpf-to-bpf calls\n");
		return -EINVAL;
	}
	for (i = 0; i < prog->len; i++, insn++) {
		if (bpf_pseudo_func(insn)) {
			/* When JIT fails the progs with callback calls
			 * have to be rejected, since interpreter doesn't support them yet.
			 */
			verbose(env, "callbacks are not allowed in non-JITed programs\n");
			return -EINVAL;
		}

		if (!bpf_pseudo_call(insn))
			continue;
		depth = get_callee_stack_depth(env, insn, i);
		if (depth < 0)
			return depth;
		err = bpf_patch_call_args(insn, depth);
		if (err) {
			verbose(env, "stack depth %d exceeds interpreter stack depth limit\n",
				depth);
			return err;
		}
	}
	err = 0;
#endif
	return err;
}

/* The function requires that first instruction in 'patch' is insnsi[prog->len - 1] */
static int add_hidden_subprog(struct bpf_verifier_env *env, struct bpf_insn *patch, int len)
{
	struct bpf_subprog_info *info = env->subprog_info;
	int cnt = env->subprog_cnt;
	struct bpf_prog *prog;

	/* We only reserve one slot for hidden subprogs in subprog_info. */
	if (env->hidden_subprog_cnt) {
		verifier_bug(env, "only one hidden subprog supported");
		return -EFAULT;
	}
	/* We're not patching any existing instruction, just appending the new
	 * ones for the hidden subprog. Hence all of the adjustment operations
	 * in bpf_patch_insn_data are no-ops.
	 */
	prog = bpf_patch_insn_data(env, env->prog->len - 1, patch, len);
	if (!prog)
		return -ENOMEM;
	env->prog = prog;
	info[cnt + 1].start = info[cnt].start;
	info[cnt].start = prog->len - len + 1;
	/* The patch ends with the exit. */
	info[cnt].exit_idx = prog->len - 1;
	env->subprog_cnt++;
	env->hidden_subprog_cnt++;
	return 0;
}

/*
 * Expand may_goto: load the count from the stack, jump to the target of
 * may_goto when it is zero, then the tail that updates the count.
 * Use gotol when the target is too far for 16-bit offset of a conditional jump.
 */
static int may_goto_expand(struct bpf_insn *insn_buf, int off, int stack_off,
			   const struct bpf_insn *tail, int tail_cnt)
{
	int cnt = 0;

	/* Forward jump has to step over the tail */
	off = off >= 0 ? off + tail_cnt : off - 1;

	insn_buf[cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_AX, BPF_REG_10, stack_off);
	if (off == (s16)off) {
		insn_buf[cnt++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_AX, 0, off);
	} else {
		insn_buf[cnt++] = BPF_JMP_IMM(BPF_JNE, BPF_REG_AX, 0, 1);
		insn_buf[cnt++] = BPF_JMP32_A(off >= 0 ? off : off - 1);
	}
	memcpy(insn_buf + cnt, tail, tail_cnt * sizeof(*tail));
	return cnt + tail_cnt;
}

/* Do various post-verification rewrites in a single program pass.
 * These rewrites simplify JIT and interpreter implementations.
 */
int bpf_do_misc_fixups(struct bpf_verifier_env *env)
{
	struct bpf_prog *prog = env->prog;
	enum bpf_attach_type eatype = prog->expected_attach_type;
	enum bpf_prog_type prog_type = resolve_prog_type(prog);
	struct bpf_insn *insn = prog->insnsi;
	const struct bpf_func_proto *fn;
	const int insn_cnt = prog->len;
	const struct bpf_map_ops *ops;
	struct bpf_insn_aux_data *aux;
	struct bpf_insn *insn_buf = env->insn_buf;
	struct bpf_prog *new_prog;
	struct bpf_map *map_ptr;
	int i, ret, cnt, delta = 0, cur_subprog = 0;
	struct bpf_subprog_info *subprogs = env->subprog_info;
	struct bpf_may_goto_budget __percpu *budget = NULL;
	u16 stack_depth = subprogs[cur_subprog].stack_depth;
	u16 stack_depth_extra = 0;

	if (env->seen_exception && !env->exception_callback_subprog) {
		struct bpf_insn *patch = insn_buf;

		*patch++ = env->prog->insnsi[insn_cnt - 1];
		*patch++ = BPF_MOV64_REG(BPF_REG_0, BPF_REG_1);
		*patch++ = BPF_EXIT_INSN();
		ret = add_hidden_subprog(env, insn_buf, patch - insn_buf);
		if (ret < 0)
			return ret;
		prog = env->prog;
		insn = prog->insnsi;

		env->exception_callback_subprog = env->subprog_cnt - 1;
		/* Don't update insn_cnt, as add_hidden_subprog always appends insns */
		bpf_mark_subprog_exc_cb(env, env->exception_callback_subprog);
	}

	for (i = 0; i < insn_cnt;) {
		if (is_addr_space_cast32(env->prog, insn)) {
			/* convert to 32-bit mov that clears upper 32-bit */
			insn->code = BPF_ALU | BPF_MOV | BPF_X;
			/* clear off and imm, so it's a normal 'wX = wY' from JIT pov */
			insn->off = 0;
			insn->imm = 0;
			goto next_insn;
		}

		if (env->insn_aux_data[i + delta].needs_zext)
			/* Convert BPF_CLASS(insn->code) == BPF_ALU64 to 32-bit ALU */
			insn->code = BPF_ALU | BPF_OP(insn->code) | BPF_SRC(insn->code);

		/* Make sdiv/smod divide-by-minus-one exceptions impossible. */
		if ((insn->code == (BPF_ALU64 | BPF_MOD | BPF_K) ||
		     insn->code == (BPF_ALU64 | BPF_DIV | BPF_K) ||
		     insn->code == (BPF_ALU | BPF_MOD | BPF_K) ||
		     insn->code == (BPF_ALU | BPF_DIV | BPF_K)) &&
		    insn->off == 1 && insn->imm == -1) {
			bool is64 = BPF_CLASS(insn->code) == BPF_ALU64;
			bool isdiv = BPF_OP(insn->code) == BPF_DIV;
			struct bpf_insn *patch = insn_buf;

			if (isdiv)
				*patch++ = BPF_RAW_INSN((is64 ? BPF_ALU64 : BPF_ALU) |
							BPF_NEG | BPF_K, insn->dst_reg,
							0, 0, 0);
			else
				*patch++ = BPF_MOV32_IMM(insn->dst_reg, 0);

			cnt = patch - insn_buf;

			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta    += cnt - 1;
			env->prog = prog = new_prog;
			insn      = new_prog->insnsi + i + delta;
			goto next_insn;
		}

		/* Make divide-by-zero and divide-by-minus-one exceptions impossible. */
		if (insn->code == (BPF_ALU64 | BPF_MOD | BPF_X) ||
		    insn->code == (BPF_ALU64 | BPF_DIV | BPF_X) ||
		    insn->code == (BPF_ALU | BPF_MOD | BPF_X) ||
		    insn->code == (BPF_ALU | BPF_DIV | BPF_X)) {
			bool is64 = BPF_CLASS(insn->code) == BPF_ALU64;
			bool isdiv = BPF_OP(insn->code) == BPF_DIV;
			bool is_sdiv = isdiv && insn->off == 1;
			bool is_smod = !isdiv && insn->off == 1;
			struct bpf_insn *patch = insn_buf;

			if (is_sdiv) {
				/* [R,W]x sdiv 0 -> 0
				 * LLONG_MIN sdiv -1 -> LLONG_MIN
				 * INT_MIN sdiv -1 -> INT_MIN
				 */
				*patch++ = BPF_MOV64_REG(BPF_REG_AX, insn->src_reg);
				*patch++ = BPF_RAW_INSN((is64 ? BPF_ALU64 : BPF_ALU) |
							BPF_ADD | BPF_K, BPF_REG_AX,
							0, 0, 1);
				*patch++ = BPF_RAW_INSN((is64 ? BPF_JMP : BPF_JMP32) |
							BPF_JGT | BPF_K, BPF_REG_AX,
							0, 4, 1);
				*patch++ = BPF_RAW_INSN((is64 ? BPF_JMP : BPF_JMP32) |
							BPF_JEQ | BPF_K, BPF_REG_AX,
							0, 1, 0);
				*patch++ = BPF_RAW_INSN((is64 ? BPF_ALU64 : BPF_ALU) |
							BPF_MOV | BPF_K, insn->dst_reg,
							0, 0, 0);
				/* BPF_NEG(LLONG_MIN) == -LLONG_MIN == LLONG_MIN */
				*patch++ = BPF_RAW_INSN((is64 ? BPF_ALU64 : BPF_ALU) |
							BPF_NEG | BPF_K, insn->dst_reg,
							0, 0, 0);
				*patch++ = BPF_JMP_IMM(BPF_JA, 0, 0, 1);
				*patch++ = *insn;
				cnt = patch - insn_buf;
			} else if (is_smod) {
				/* [R,W]x mod 0 -> [R,W]x */
				/* [R,W]x mod -1 -> 0 */
				*patch++ = BPF_MOV64_REG(BPF_REG_AX, insn->src_reg);
				*patch++ = BPF_RAW_INSN((is64 ? BPF_ALU64 : BPF_ALU) |
							BPF_ADD | BPF_K, BPF_REG_AX,
							0, 0, 1);
				*patch++ = BPF_RAW_INSN((is64 ? BPF_JMP : BPF_JMP32) |
							BPF_JGT | BPF_K, BPF_REG_AX,
							0, 3, 1);
				*patch++ = BPF_RAW_INSN((is64 ? BPF_JMP : BPF_JMP32) |
							BPF_JEQ | BPF_K, BPF_REG_AX,
							0, 3 + (is64 ? 0 : 1), 1);
				*patch++ = BPF_MOV32_IMM(insn->dst_reg, 0);
				*patch++ = BPF_JMP_IMM(BPF_JA, 0, 0, 1);
				*patch++ = *insn;

				if (!is64) {
					*patch++ = BPF_JMP_IMM(BPF_JA, 0, 0, 1);
					*patch++ = BPF_MOV32_REG(insn->dst_reg, insn->dst_reg);
				}
				cnt = patch - insn_buf;
			} else if (isdiv) {
				/* [R,W]x div 0 -> 0 */
				*patch++ = BPF_RAW_INSN((is64 ? BPF_JMP : BPF_JMP32) |
							BPF_JNE | BPF_K, insn->src_reg,
							0, 2, 0);
				*patch++ = BPF_ALU32_REG(BPF_XOR, insn->dst_reg, insn->dst_reg);
				*patch++ = BPF_JMP_IMM(BPF_JA, 0, 0, 1);
				*patch++ = *insn;
				cnt = patch - insn_buf;
			} else {
				/* [R,W]x mod 0 -> [R,W]x */
				*patch++ = BPF_RAW_INSN((is64 ? BPF_JMP : BPF_JMP32) |
							BPF_JEQ | BPF_K, insn->src_reg,
							0, 1 + (is64 ? 0 : 1), 0);
				*patch++ = *insn;

				if (!is64) {
					*patch++ = BPF_JMP_IMM(BPF_JA, 0, 0, 1);
					*patch++ = BPF_MOV32_REG(insn->dst_reg, insn->dst_reg);
				}
				cnt = patch - insn_buf;
			}

			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta    += cnt - 1;
			env->prog = prog = new_prog;
			insn      = new_prog->insnsi + i + delta;
			goto next_insn;
		}

		/* Make it impossible to de-reference a userspace address */
		if (BPF_CLASS(insn->code) == BPF_LDX &&
		    (BPF_MODE(insn->code) == BPF_PROBE_MEM ||
		     BPF_MODE(insn->code) == BPF_PROBE_MEMSX)) {
			struct bpf_insn *patch = insn_buf;
			u64 uaddress_limit = bpf_arch_uaddress_limit();

			if (!uaddress_limit)
				goto next_insn;

			*patch++ = BPF_MOV64_REG(BPF_REG_AX, insn->src_reg);
			if (insn->off)
				*patch++ = BPF_ALU64_IMM(BPF_ADD, BPF_REG_AX, insn->off);
			*patch++ = BPF_ALU64_IMM(BPF_RSH, BPF_REG_AX, 32);
			*patch++ = BPF_JMP_IMM(BPF_JLE, BPF_REG_AX, uaddress_limit >> 32, 2);
			*patch++ = *insn;
			*patch++ = BPF_JMP_IMM(BPF_JA, 0, 0, 1);
			*patch++ = BPF_MOV64_IMM(insn->dst_reg, 0);

			cnt = patch - insn_buf;
			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta    += cnt - 1;
			env->prog = prog = new_prog;
			insn      = new_prog->insnsi + i + delta;
			goto next_insn;
		}

		/* Implement LD_ABS and LD_IND with a rewrite, if supported by the program type. */
		if (BPF_CLASS(insn->code) == BPF_LD &&
		    (BPF_MODE(insn->code) == BPF_ABS ||
		     BPF_MODE(insn->code) == BPF_IND)) {
			cnt = env->ops->gen_ld_abs(insn, insn_buf);
			if (cnt == 0 || cnt >= INSN_BUF_SIZE) {
				verifier_bug(env, "%d insns generated for ld_abs", cnt);
				return -EFAULT;
			}

			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta    += cnt - 1;
			env->prog = prog = new_prog;
			insn      = new_prog->insnsi + i + delta;
			goto next_insn;
		}

		/* Rewrite pointer arithmetic to mitigate speculation attacks. */
		if (insn->code == (BPF_ALU64 | BPF_ADD | BPF_X) ||
		    insn->code == (BPF_ALU64 | BPF_SUB | BPF_X)) {
			const u8 code_add = BPF_ALU64 | BPF_ADD | BPF_X;
			const u8 code_sub = BPF_ALU64 | BPF_SUB | BPF_X;
			struct bpf_insn *patch = insn_buf;
			bool issrc, isneg, isimm;
			u32 off_reg;

			aux = &env->insn_aux_data[i + delta];
			if (!aux->alu_state ||
			    aux->alu_state == BPF_ALU_NON_POINTER)
				goto next_insn;

			isneg = aux->alu_state & BPF_ALU_NEG_VALUE;
			issrc = (aux->alu_state & BPF_ALU_SANITIZE) ==
				BPF_ALU_SANITIZE_SRC;
			isimm = aux->alu_state & BPF_ALU_IMMEDIATE;

			off_reg = issrc ? insn->src_reg : insn->dst_reg;
			if (isimm) {
				*patch++ = BPF_MOV32_IMM(BPF_REG_AX, aux->alu_limit);
			} else {
				if (isneg)
					*patch++ = BPF_ALU64_IMM(BPF_MUL, off_reg, -1);
				*patch++ = BPF_MOV32_IMM(BPF_REG_AX, aux->alu_limit);
				*patch++ = BPF_ALU64_REG(BPF_SUB, BPF_REG_AX, off_reg);
				*patch++ = BPF_ALU64_REG(BPF_OR, BPF_REG_AX, off_reg);
				*patch++ = BPF_ALU64_IMM(BPF_NEG, BPF_REG_AX, 0);
				*patch++ = BPF_ALU64_IMM(BPF_ARSH, BPF_REG_AX, 63);
				*patch++ = BPF_ALU64_REG(BPF_AND, BPF_REG_AX, off_reg);
			}
			if (!issrc)
				*patch++ = BPF_MOV64_REG(insn->dst_reg, insn->src_reg);
			insn->src_reg = BPF_REG_AX;
			if (isneg)
				insn->code = insn->code == code_add ?
					     code_sub : code_add;
			*patch++ = *insn;
			if (issrc && isneg && !isimm)
				*patch++ = BPF_ALU64_IMM(BPF_MUL, off_reg, -1);
			cnt = patch - insn_buf;

			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta    += cnt - 1;
			env->prog = prog = new_prog;
			insn      = new_prog->insnsi + i + delta;
			goto next_insn;
		}

		if (bpf_is_may_goto_insn(insn) && bpf_jit_supports_timed_may_goto()) {
			int stack_off_cnt = -stack_depth - 16;
			/*
			 * AX is used as an argument to pass in stack_off_cnt
			 * (to add to r10/fp), and also as the return value of
			 * the call to arch_bpf_timed_may_goto.
			 */
			struct bpf_insn tail[] = {
				BPF_ALU64_IMM(BPF_SUB, BPF_REG_AX, 1),
				BPF_JMP_IMM(BPF_JNE, BPF_REG_AX, 0, 2),
				BPF_MOV64_IMM(BPF_REG_AX, stack_off_cnt),
				BPF_EMIT_CALL(arch_bpf_timed_may_goto),
				BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_AX, stack_off_cnt),
			};

			/*
			 * Two 8 byte slots, depth-16 stores the count, and
			 * depth-8 stores the start timestamp of the loop.
			 *
			 * The starting value of count is BPF_MAX_TIMED_LOOPS
			 * (0xffff).  Every iteration loads it and subs it by 1,
			 * until the value becomes 0 in AX (thus, 1 in stack),
			 * after which we call arch_bpf_timed_may_goto, which
			 * either sets AX to 0xffff to keep looping, or to 0
			 * upon timeout. AX is then stored into the stack. In
			 * the next iteration, we either see 0 and break out, or
			 * continue iterating until the next time value is 0
			 * after subtraction, rinse and repeat.
			 */
			stack_depth_extra = 16;
			cnt = may_goto_expand(insn_buf, insn->off, stack_off_cnt,
					      tail, ARRAY_SIZE(tail));

			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta += cnt - 1;
			env->prog = prog = new_prog;
			insn = new_prog->insnsi + i + delta;
			goto next_insn;
		} else if (bpf_is_may_goto_insn(insn)) {
			int stack_off = -stack_depth - 8;
			struct bpf_insn tail[] = {
				BPF_ALU64_IMM(BPF_SUB, BPF_REG_AX, 1),
				BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_AX, stack_off),
			};

			stack_depth_extra = 8;
			cnt = may_goto_expand(insn_buf, insn->off, stack_off,
					      tail, ARRAY_SIZE(tail));

			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta += cnt - 1;
			env->prog = prog = new_prog;
			insn = new_prog->insnsi + i + delta;
			goto next_insn;
		}

		if (bpf_jit_supports_percpu_insn() &&
		    insn->code == (BPF_LD | BPF_IMM | BPF_DW) &&
		    (insn->src_reg == BPF_PSEUDO_MAP_VALUE ||
		     insn->src_reg == BPF_PSEUDO_MAP_IDX_VALUE)) {
			struct bpf_map *map;

			aux = &env->insn_aux_data[i + delta];
			map = env->used_maps[aux->map_index];
			if (map->map_type != BPF_MAP_TYPE_PERCPU_ARRAY)
				goto next_insn;

			prog->jit_required = true;

			/*
			 * We are *skipping* first half of ld_imm64 insn
			 * with 'i++;', patching over second half of it
			 * with that same half + mov64_percpu_reg insn.
			 * All because bpf_patch_insn_data() can only
			 * replace one 8-byte insn, which does not work
			 * well for ld_imm64 insn.
			 */

			insn_buf[0] = insn[1];
			insn_buf[1] = BPF_MOV64_PERCPU_REG(insn->dst_reg, insn->dst_reg);
			cnt = 2;

			i++;
			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta    += cnt - 1;
			env->prog = prog = new_prog;
			insn      = new_prog->insnsi + i + delta;
			goto next_insn;
		}

		if (insn->code != (BPF_JMP | BPF_CALL))
			goto next_insn;
		if (insn->src_reg == BPF_PSEUDO_CALL)
			goto next_insn;
		if (insn->src_reg == BPF_PSEUDO_KFUNC_CALL) {
			ret = bpf_fixup_kfunc_call(env, insn, insn_buf, i + delta, &cnt);
			if (ret)
				return ret;
			if (cnt == 0)
				goto next_insn;

			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta	 += cnt - 1;
			env->prog = prog = new_prog;
			insn	  = new_prog->insnsi + i + delta;
			goto next_insn;
		}

		/* Skip inlining the helper call if the JIT does it. */
		if (bpf_jit_inlines_helper_call(insn->imm)) {
			prog->jit_required = 1;
			goto next_insn;
		}

		if (insn->imm == BPF_FUNC_get_route_realm)
			prog->dst_needed = 1;
		if (insn->imm == BPF_FUNC_get_prandom_u32)
			bpf_user_rnd_init_once();
		if (insn->imm == BPF_FUNC_override_return)
			prog->kprobe_override = 1;
		if (insn->imm == BPF_FUNC_tail_call) {
			/* If we tail call into other programs, we
			 * cannot make any assumptions since they can
			 * be replaced dynamically during runtime in
			 * the program array.
			 */
			prog->cb_access = 1;
			if (!bpf_allow_tail_call_in_subprogs(env))
				prog->aux->stack_depth = MAX_BPF_STACK;
			prog->aux->max_pkt_offset = MAX_PACKET_OFF;
			prog->aux->max_rdonly_access = U32_MAX;
			prog->aux->max_rdwr_access = U32_MAX;
			if (prog->type == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE)
				prog->aux->max_tp_access = U32_MAX;

			/* mark bpf_tail_call as different opcode to avoid
			 * conditional branch in the interpreter for every normal
			 * call and to prevent accidental JITing by JIT compiler
			 * that doesn't support bpf_tail_call yet
			 */
			insn->imm = 0;
			insn->code = BPF_JMP | BPF_TAIL_CALL;

			aux = &env->insn_aux_data[i + delta];
			if (env->bpf_capable && !prog->blinding_requested &&
			    prog->jit_requested &&
			    !bpf_map_key_poisoned(aux) &&
			    !bpf_map_ptr_poisoned(aux) &&
			    !bpf_map_ptr_unpriv(aux)) {
				struct bpf_jit_poke_descriptor desc = {
					.reason = BPF_POKE_REASON_TAIL_CALL,
					.tail_call.map = aux->map_ptr_state.map_ptr,
					.tail_call.key = bpf_map_key_immediate(aux),
					.insn_idx = i + delta,
				};

				ret = bpf_jit_add_poke_descriptor(prog, &desc);
				if (ret < 0) {
					verbose(env, "adding tail call poke descriptor failed\n");
					return ret;
				}

				insn->imm = ret + 1;
				goto next_insn;
			}

			if (!bpf_map_ptr_unpriv(aux))
				goto next_insn;

			/* instead of changing every JIT dealing with tail_call
			 * emit two extra insns:
			 * if (index >= max_entries) goto out;
			 * index &= array->index_mask;
			 * to avoid out-of-bounds cpu speculation
			 */
			if (bpf_map_ptr_poisoned(aux)) {
				verbose(env, "tail_call abusing map_ptr\n");
				return -EINVAL;
			}

			map_ptr = aux->map_ptr_state.map_ptr;
			insn_buf[0] = BPF_JMP_IMM(BPF_JGE, BPF_REG_3,
						  map_ptr->max_entries, 2);
			insn_buf[1] = BPF_ALU32_IMM(BPF_AND, BPF_REG_3,
						    container_of(map_ptr,
								 struct bpf_array,
								 map)->index_mask);
			insn_buf[2] = *insn;
			cnt = 3;
			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta    += cnt - 1;
			env->prog = prog = new_prog;
			insn      = new_prog->insnsi + i + delta;
			goto next_insn;
		}

		aux = &env->insn_aux_data[i + delta];
		if (aux->arg_prog) {
			/* The verifier will process callback_fn as many times as necessary
			 * with different maps and the register states prepared by
			 * set_timer_callback_state will be accurate.
			 *
			 * The following use case is valid:
			 *   map1 is shared by prog1, prog2, prog3.
			 *   prog1 calls bpf_timer_init for some map1 elements
			 *   prog2 calls bpf_timer_set_callback for some map1 elements.
			 *     Those that were not bpf_timer_init-ed will return -EINVAL.
			 *   prog3 calls bpf_timer_start for some map1 elements.
			 *     Those that were not both bpf_timer_init-ed and
			 *     bpf_timer_set_callback-ed will return -EINVAL.
			 */
			struct bpf_insn ld_addrs[2] = {
				BPF_LD_IMM64(aux->arg_prog, (long)prog->aux),
			};

			insn_buf[0] = ld_addrs[0];
			insn_buf[1] = ld_addrs[1];
			insn_buf[2] = *insn;
			cnt = 3;

			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta    += cnt - 1;
			env->prog = prog = new_prog;
			insn      = new_prog->insnsi + i + delta;
			goto patch_call_imm;
		}

		/* bpf_per_cpu_ptr() and bpf_this_cpu_ptr() */
		if (env->insn_aux_data[i + delta].call_with_percpu_alloc_ptr) {
			/* patch with 'r1 = *(u64 *)(r1 + 0)' since for percpu data,
			 * bpf_mem_alloc() returns a ptr to the percpu data ptr.
			 */
			insn_buf[0] = BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_1, 0);
			insn_buf[1] = *insn;
			cnt = 2;

			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta += cnt - 1;
			env->prog = prog = new_prog;
			insn = new_prog->insnsi + i + delta;
			goto patch_call_imm;
		}

		/* BPF_EMIT_CALL() assumptions in some of the map_gen_lookup
		 * and other inlining handlers are currently limited to 64 bit
		 * only.
		 */
		if (prog->jit_requested && BITS_PER_LONG == 64 &&
		    (insn->imm == BPF_FUNC_map_lookup_elem ||
		     insn->imm == BPF_FUNC_map_update_elem ||
		     insn->imm == BPF_FUNC_map_delete_elem ||
		     insn->imm == BPF_FUNC_map_push_elem   ||
		     insn->imm == BPF_FUNC_map_pop_elem    ||
		     insn->imm == BPF_FUNC_map_peek_elem   ||
		     insn->imm == BPF_FUNC_redirect_map    ||
		     insn->imm == BPF_FUNC_for_each_map_elem ||
		     insn->imm == BPF_FUNC_map_lookup_percpu_elem)) {
			aux = &env->insn_aux_data[i + delta];
			if (bpf_map_ptr_poisoned(aux))
				goto patch_call_imm;

			map_ptr = aux->map_ptr_state.map_ptr;
			ops = map_ptr->ops;
			if (insn->imm == BPF_FUNC_map_lookup_elem &&
			    ops->map_gen_lookup) {
				cnt = ops->map_gen_lookup(map_ptr, insn_buf);
				if (cnt == -EOPNOTSUPP)
					goto patch_map_ops_generic;
				if (cnt <= 0 || cnt >= INSN_BUF_SIZE) {
					verifier_bug(env, "%d insns generated for map lookup", cnt);
					return -EFAULT;
				}

				if (bpf_map_is_percpu_map(map_ptr->map_type))
					prog->jit_required = true;

				new_prog = bpf_patch_insn_data(env, i + delta,
							       insn_buf, cnt);
				if (!new_prog)
					return -ENOMEM;

				delta    += cnt - 1;
				env->prog = prog = new_prog;
				insn      = new_prog->insnsi + i + delta;
				goto next_insn;
			}

			BUILD_BUG_ON(!__same_type(ops->map_lookup_elem,
				     (void *(*)(struct bpf_map *map, void *key))NULL));
			BUILD_BUG_ON(!__same_type(ops->map_delete_elem,
				     (long (*)(struct bpf_map *map, void *key))NULL));
			BUILD_BUG_ON(!__same_type(ops->map_update_elem,
				     (long (*)(struct bpf_map *map, void *key, void *value,
					      u64 flags))NULL));
			BUILD_BUG_ON(!__same_type(ops->map_push_elem,
				     (long (*)(struct bpf_map *map, void *value,
					      u64 flags))NULL));
			BUILD_BUG_ON(!__same_type(ops->map_pop_elem,
				     (long (*)(struct bpf_map *map, void *value))NULL));
			BUILD_BUG_ON(!__same_type(ops->map_peek_elem,
				     (long (*)(struct bpf_map *map, void *value))NULL));
			BUILD_BUG_ON(!__same_type(ops->map_redirect,
				     (long (*)(struct bpf_map *map, u64 index, u64 flags))NULL));
			BUILD_BUG_ON(!__same_type(ops->map_for_each_callback,
				     (long (*)(struct bpf_map *map,
					      bpf_callback_t callback_fn,
					      void *callback_ctx,
					      u64 flags))NULL));
			BUILD_BUG_ON(!__same_type(ops->map_lookup_percpu_elem,
				     (void *(*)(struct bpf_map *map, void *key, u32 cpu))NULL));

patch_map_ops_generic:
			switch (insn->imm) {
			case BPF_FUNC_map_lookup_elem:
				insn->imm = BPF_CALL_IMM(ops->map_lookup_elem);
				goto next_insn;
			case BPF_FUNC_map_update_elem:
				insn->imm = BPF_CALL_IMM(ops->map_update_elem);
				goto next_insn;
			case BPF_FUNC_map_delete_elem:
				insn->imm = BPF_CALL_IMM(ops->map_delete_elem);
				goto next_insn;
			case BPF_FUNC_map_push_elem:
				insn->imm = BPF_CALL_IMM(ops->map_push_elem);
				goto next_insn;
			case BPF_FUNC_map_pop_elem:
				insn->imm = BPF_CALL_IMM(ops->map_pop_elem);
				goto next_insn;
			case BPF_FUNC_map_peek_elem:
				insn->imm = BPF_CALL_IMM(ops->map_peek_elem);
				goto next_insn;
			case BPF_FUNC_redirect_map:
				insn->imm = BPF_CALL_IMM(ops->map_redirect);
				goto next_insn;
			case BPF_FUNC_for_each_map_elem:
				insn->imm = BPF_CALL_IMM(ops->map_for_each_callback);
				goto next_insn;
			case BPF_FUNC_map_lookup_percpu_elem:
				insn->imm = BPF_CALL_IMM(ops->map_lookup_percpu_elem);
				goto next_insn;
			}

			goto patch_call_imm;
		}

		/* Implement bpf_jiffies64 inline. */
		if (prog->jit_requested && BITS_PER_LONG == 64 &&
		    insn->imm == BPF_FUNC_jiffies64) {
			struct bpf_insn ld_jiffies_addr[2] = {
				BPF_LD_IMM64(BPF_REG_0,
					     (unsigned long)&jiffies),
			};

			insn_buf[0] = ld_jiffies_addr[0];
			insn_buf[1] = ld_jiffies_addr[1];
			insn_buf[2] = BPF_LDX_MEM(BPF_DW, BPF_REG_0,
						  BPF_REG_0, 0);
			cnt = 3;

			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf,
						       cnt);
			if (!new_prog)
				return -ENOMEM;

			delta    += cnt - 1;
			env->prog = prog = new_prog;
			insn      = new_prog->insnsi + i + delta;
			goto next_insn;
		}

#if defined(CONFIG_X86_64) && !defined(CONFIG_UML)
		/* Implement bpf_get_smp_processor_id() inline. */
		if (insn->imm == BPF_FUNC_get_smp_processor_id &&
		    bpf_verifier_inlines_helper_call(env, insn->imm)) {
			/* BPF_FUNC_get_smp_processor_id inlining is an
			 * optimization, so if cpu_number is ever
			 * changed in some incompatible and hard to support
			 * way, it's fine to back out this inlining logic
			 */
#ifdef CONFIG_SMP
			prog->jit_required = true;
			insn_buf[0] = BPF_MOV64_IMM(BPF_REG_0, (u32)(unsigned long)&cpu_number);
			insn_buf[1] = BPF_MOV64_PERCPU_REG(BPF_REG_0, BPF_REG_0);
			insn_buf[2] = BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_0, 0);
			cnt = 3;
#else
			insn_buf[0] = BPF_ALU32_REG(BPF_XOR, BPF_REG_0, BPF_REG_0);
			cnt = 1;
#endif
			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta    += cnt - 1;
			env->prog = prog = new_prog;
			insn      = new_prog->insnsi + i + delta;
			goto next_insn;
		}

		/* Implement bpf_get_current_task() and bpf_get_current_task_btf() inline. */
		if ((insn->imm == BPF_FUNC_get_current_task || insn->imm == BPF_FUNC_get_current_task_btf) &&
		    bpf_verifier_inlines_helper_call(env, insn->imm)) {
			prog->jit_required = true;
			insn_buf[0] = BPF_MOV64_IMM(BPF_REG_0, (u32)(unsigned long)&current_task);
			insn_buf[1] = BPF_MOV64_PERCPU_REG(BPF_REG_0, BPF_REG_0);
			insn_buf[2] = BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_0, 0);
			cnt = 3;

			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta    += cnt - 1;
			env->prog = prog = new_prog;
			insn      = new_prog->insnsi + i + delta;
			goto next_insn;
		}
#endif
		/* Implement bpf_get_func_arg inline. */
		if (prog_type == BPF_PROG_TYPE_TRACING &&
		    insn->imm == BPF_FUNC_get_func_arg) {
			if (eatype == BPF_TRACE_RAW_TP) {
				int nr_args = btf_type_vlen(prog->aux->attach_func_proto);

				/* skip 'void *__data' in btf_trace_##name() and save to reg0 */
				insn_buf[0] = BPF_MOV64_IMM(BPF_REG_0, nr_args - 1);
				cnt = 1;
			} else {
				/* Load nr_args from ctx - 8 */
				insn_buf[0] = BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, -8);
				insn_buf[1] = BPF_ALU64_IMM(BPF_AND, BPF_REG_0, 0xFF);
				cnt = 2;
			}
			insn_buf[cnt++] = BPF_JMP32_REG(BPF_JGE, BPF_REG_2, BPF_REG_0, 6);
			insn_buf[cnt++] = BPF_ALU32_IMM(BPF_LSH, BPF_REG_2, 3);
			insn_buf[cnt++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_2, BPF_REG_1);
			insn_buf[cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_2, 0);
			insn_buf[cnt++] = BPF_STX_MEM(BPF_DW, BPF_REG_3, BPF_REG_0, 0);
			insn_buf[cnt++] = BPF_MOV64_IMM(BPF_REG_0, 0);
			insn_buf[cnt++] = BPF_JMP_A(1);
			insn_buf[cnt++] = BPF_MOV64_IMM(BPF_REG_0, -EINVAL);

			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta    += cnt - 1;
			env->prog = prog = new_prog;
			insn      = new_prog->insnsi + i + delta;
			goto next_insn;
		}

		/* Implement bpf_get_func_ret inline. */
		if (prog_type == BPF_PROG_TYPE_TRACING &&
		    insn->imm == BPF_FUNC_get_func_ret) {
			if (eatype == BPF_TRACE_FEXIT ||
			    eatype == BPF_TRACE_FSESSION ||
			    eatype == BPF_TRACE_FEXIT_MULTI ||
			    eatype == BPF_TRACE_FSESSION_MULTI ||
			    eatype == BPF_MODIFY_RETURN) {
				/* Load nr_args from ctx - 8 */
				insn_buf[0] = BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, -8);
				insn_buf[1] = BPF_ALU64_IMM(BPF_AND, BPF_REG_0, 0xFF);
				insn_buf[2] = BPF_ALU64_IMM(BPF_LSH, BPF_REG_0, 3);
				insn_buf[3] = BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_1);
				insn_buf[4] = BPF_LDX_MEM(BPF_DW, BPF_REG_3, BPF_REG_0, 0);
				insn_buf[5] = BPF_STX_MEM(BPF_DW, BPF_REG_2, BPF_REG_3, 0);
				insn_buf[6] = BPF_MOV64_IMM(BPF_REG_0, 0);
				cnt = 7;
			} else {
				insn_buf[0] = BPF_MOV64_IMM(BPF_REG_0, -EOPNOTSUPP);
				cnt = 1;
			}

			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta    += cnt - 1;
			env->prog = prog = new_prog;
			insn      = new_prog->insnsi + i + delta;
			goto next_insn;
		}

		/* Implement get_func_arg_cnt inline. */
		if (prog_type == BPF_PROG_TYPE_TRACING &&
		    insn->imm == BPF_FUNC_get_func_arg_cnt) {
			if (eatype == BPF_TRACE_RAW_TP) {
				int nr_args = btf_type_vlen(prog->aux->attach_func_proto);

				/* skip 'void *__data' in btf_trace_##name() and save to reg0 */
				insn_buf[0] = BPF_MOV64_IMM(BPF_REG_0, nr_args - 1);
				cnt = 1;
			} else {
				/* Load nr_args from ctx - 8 */
				insn_buf[0] = BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, -8);
				insn_buf[1] = BPF_ALU64_IMM(BPF_AND, BPF_REG_0, 0xFF);
				cnt = 2;
			}

			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta    += cnt - 1;
			env->prog = prog = new_prog;
			insn      = new_prog->insnsi + i + delta;
			goto next_insn;
		}

		/* Implement bpf_get_func_ip inline. */
		if (prog_type == BPF_PROG_TYPE_TRACING &&
		    insn->imm == BPF_FUNC_get_func_ip) {
			/* Load IP address from ctx - 16 */
			insn_buf[0] = BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, -16);

			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, 1);
			if (!new_prog)
				return -ENOMEM;

			env->prog = prog = new_prog;
			insn      = new_prog->insnsi + i + delta;
			goto next_insn;
		}

		/* Implement bpf_get_branch_snapshot inline. */
		if (IS_ENABLED(CONFIG_PERF_EVENTS) &&
		    prog->jit_requested && BITS_PER_LONG == 64 &&
		    insn->imm == BPF_FUNC_get_branch_snapshot) {
			/* We are dealing with the following func protos:
			 * u64 bpf_get_branch_snapshot(void *buf, u32 size, u64 flags);
			 * int perf_snapshot_branch_stack(struct perf_branch_entry *entries, u32 cnt);
			 */
			const u32 br_entry_size = sizeof(struct perf_branch_entry);

			/* struct perf_branch_entry is part of UAPI and is
			 * used as an array element, so extremely unlikely to
			 * ever grow or shrink
			 */
			BUILD_BUG_ON(br_entry_size != 24);

			/* if (unlikely(flags)) return -EINVAL */
			insn_buf[0] = BPF_JMP_IMM(BPF_JNE, BPF_REG_3, 0, 7);

			/* Transform size (bytes) into number of entries (cnt = size / 24).
			 * But to avoid expensive division instruction, we implement
			 * divide-by-3 through multiplication, followed by further
			 * division by 8 through 3-bit right shift.
			 * Refer to book "Hacker's Delight, 2nd ed." by Henry S. Warren, Jr.,
			 * p. 227, chapter "Unsigned Division by 3" for details and proofs.
			 *
			 * N / 3 <=> M * N / 2^33, where M = (2^33 + 1) / 3 = 0xaaaaaaab.
			 */
			insn_buf[1] = BPF_MOV32_IMM(BPF_REG_0, 0xaaaaaaab);
			insn_buf[2] = BPF_ALU64_REG(BPF_MUL, BPF_REG_2, BPF_REG_0);
			insn_buf[3] = BPF_ALU64_IMM(BPF_RSH, BPF_REG_2, 36);

			/* call perf_snapshot_branch_stack implementation */
			insn_buf[4] = BPF_EMIT_CALL(static_call_query(perf_snapshot_branch_stack));
			/* if (entry_cnt == 0) return -ENOENT */
			insn_buf[5] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 4);
			/* return entry_cnt * sizeof(struct perf_branch_entry) */
			insn_buf[6] = BPF_ALU32_IMM(BPF_MUL, BPF_REG_0, br_entry_size);
			insn_buf[7] = BPF_JMP_A(3);
			/* return -EINVAL; */
			insn_buf[8] = BPF_MOV64_IMM(BPF_REG_0, -EINVAL);
			insn_buf[9] = BPF_JMP_A(1);
			/* return -ENOENT; */
			insn_buf[10] = BPF_MOV64_IMM(BPF_REG_0, -ENOENT);
			cnt = 11;

			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta    += cnt - 1;
			env->prog = prog = new_prog;
			insn      = new_prog->insnsi + i + delta;
			goto next_insn;
		}

		/* Implement bpf_kptr_xchg inline */
		if (prog->jit_requested && BITS_PER_LONG == 64 &&
		    insn->imm == BPF_FUNC_kptr_xchg &&
		    bpf_jit_supports_ptr_xchg()) {
			insn_buf[0] = BPF_MOV64_REG(BPF_REG_0, BPF_REG_2);
			insn_buf[1] = BPF_ATOMIC_OP(BPF_DW, BPF_XCHG, BPF_REG_1, BPF_REG_0, 0);
			cnt = 2;

			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta    += cnt - 1;
			env->prog = prog = new_prog;
			insn      = new_prog->insnsi + i + delta;
			goto next_insn;
		}
patch_call_imm:
		fn = env->ops->get_func_proto(insn->imm, env->prog);
		/* all functions that have prototype and verifier allowed
		 * programs to call them, must be real in-kernel functions
		 */
		if (!fn->func) {
			verifier_bug(env,
				     "not inlined functions %s#%d is missing func",
				     func_id_name(insn->imm), insn->imm);
			return -EFAULT;
		}
		insn->imm = BPF_CALL_IMM(fn->func);
next_insn:
		if (subprogs[cur_subprog + 1].start == i + delta + 1) {
			subprogs[cur_subprog].stack_depth += stack_depth_extra;
			subprogs[cur_subprog].stack_extra = stack_depth_extra;

			stack_depth = subprogs[cur_subprog].stack_depth;
			if (stack_depth > MAX_BPF_STACK && !prog->jit_requested) {
				verbose(env, "stack size %d(extra %d) is too large\n",
					stack_depth, stack_depth_extra);
				return -EINVAL;
			}
			cur_subprog++;
			stack_depth = subprogs[cur_subprog].stack_depth;
			stack_depth_extra = 0;
		}
		i++;
		insn++;
	}

	env->prog->aux->stack_depth = subprogs[0].stack_depth;
	/*
	 * One time slice for all frames of a run, see bpf_check_timed_may_goto(). It finds
	 * the prog with a walk of the stack, like bpf_throw() does. An extension is entered by
	 * the prog that it extends, it has no way to tell one run from another.
	 */
	for (i = 1; i < env->subprog_cnt; i++) {
		if (!subprogs[i].stack_extra || !bpf_jit_supports_timed_may_goto() ||
		    !bpf_jit_supports_percpu_insn() || !bpf_jit_supports_exceptions() ||
		    !prog->jit_requested || prog->type == BPF_PROG_TYPE_EXT)
			continue;
		budget = alloc_percpu_gfp(struct bpf_may_goto_budget, GFP_KERNEL_ACCOUNT);
		if (!budget)
			return -ENOMEM;
		prog->aux->may_goto_budget = budget;
		prog->jit_required = 1;
		break;
	}
	/*
	 * What a subprog has left of the count when it returns is what is left for the run,
	 * unless its callees have left less, or the time is up. R1-R3 are dead at exit.
	 */
	for (i = 1; budget && i < env->subprog_cnt; i++) {
		int off_count = offsetof(struct bpf_may_goto_budget, count);
		struct bpf_insn ld[] = { BPF_LD_IMM64(BPF_REG_1, (long)budget) };
		int j, cnt;

		if (!subprogs[i].stack_extra)
			continue;
		for (j = subprogs[i].start; j < subprogs[i + 1].start; j++) {
			if (bpf_is_ldimm64(&prog->insnsi[j])) {
				j++;
				continue;
			}
			if (prog->insnsi[j].code != (BPF_JMP | BPF_EXIT))
				continue;
			cnt = 0;
			insn_buf[cnt++] = ld[0];
			insn_buf[cnt++] = ld[1];
			insn_buf[cnt++] = BPF_MOV64_PERCPU_REG(BPF_REG_1, BPF_REG_1);
			insn_buf[cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_FP,
						      -subprogs[i].stack_depth);
			insn_buf[cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_3, BPF_REG_1, off_count);
			insn_buf[cnt++] = BPF_JMP_REG(BPF_JLE, BPF_REG_3, BPF_REG_2, 1);
			insn_buf[cnt++] = BPF_STX_MEM(BPF_DW, BPF_REG_1, BPF_REG_2, off_count);
			insn_buf[cnt++] = prog->insnsi[j];
			new_prog = bpf_patch_insn_data(env, j, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;
			env->prog = prog = new_prog;
			j += cnt - 1;
		}
	}
	for (i = 0; i < env->subprog_cnt; i++) {
		int delta = bpf_jit_supports_timed_may_goto() ? 2 : 1;
		int subprog_start = subprogs[i].start;
		int stack_slots = subprogs[i].stack_extra / 8;
		int off_start = offsetof(struct bpf_may_goto_budget, start);
		int off_count = offsetof(struct bpf_may_goto_budget, count);
		/* a run begins. For async callbacks see bpf_prog_begin_run() */
		bool entry = budget && !i;
		int slots = delta, cnt = 0;

		if (!stack_slots && !entry)
			continue;
		/* We need two slots in case timed may_goto is supported. */
		if (stack_slots > slots) {
			verifier_bug(env, "stack_slots supports may_goto only");
			return -EFAULT;
		}

		stack_depth = subprogs[i].stack_depth;
		if (budget) {
			struct bpf_insn ld[] = { BPF_LD_IMM64(BPF_REG_0, (long)budget) };

			/* R0 has nothing at the entry */
			insn_buf[cnt++] = ld[0];
			insn_buf[cnt++] = ld[1];
			insn_buf[cnt++] = BPF_MOV64_PERCPU_REG(BPF_REG_0, BPF_REG_0);
		}
		if (entry) {
			insn_buf[cnt++] = BPF_ST_MEM(BPF_DW, BPF_REG_0, off_start, 0);
			insn_buf[cnt++] = BPF_ST_MEM(BPF_DW, BPF_REG_0, off_count,
						     BPF_MAX_TIMED_LOOPS);
		}
		if (!stack_slots) {
			/* nothing to count in this one */
		} else if (budget && !entry) {
			insn_buf[cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_0, off_count);
			insn_buf[cnt++] = BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_0, -stack_depth);
			insn_buf[cnt++] = BPF_ST_MEM(BPF_DW, BPF_REG_FP, -stack_depth + 8, 0);
		} else if (bpf_jit_supports_timed_may_goto()) {
			insn_buf[cnt++] = BPF_ST_MEM(BPF_DW, BPF_REG_FP, -stack_depth,
						     BPF_MAX_TIMED_LOOPS);
			insn_buf[cnt++] = BPF_ST_MEM(BPF_DW, BPF_REG_FP, -stack_depth + 8, 0);
		} else {
			/* Add ST insn to subprog prologue to init extra stack */
			insn_buf[cnt++] = BPF_ST_MEM(BPF_DW, BPF_REG_FP, -stack_depth,
						     BPF_MAX_LOOPS);
		}
		/* Copy first actual insn to preserve it */
		insn_buf[cnt] = env->prog->insnsi[subprog_start];
		ret = bpf_adj_moved_insn(&insn_buf[cnt], cnt);
		if (ret) {
			verbose(env, "insn %d cannot be patched due to 16-bit range\n",
				env->insn_aux_data[subprog_start].orig_idx);
			return ret;
		}
		cnt++;

		new_prog = __bpf_patch_insn_data(env, subprog_start, insn_buf, cnt,
						 BPF_PATCH_MOVE_TARGET);
		if (!new_prog)
			return -ENOMEM;
		env->prog = prog = new_prog;
		/*
		 * If may_goto is a first insn of a prog there could be a jmp
		 * insn that points to it, hence adjust all such jmps to point
		 * to insn after BPF_ST that inits may_goto count.
		 * Adjustment will succeed because bpf_patch_insn_data() didn't fail.
		 */
		WARN_ON(adjust_jmp_off(env->prog, subprog_start, cnt - 1));
	}

	/* Since poke tab is now finalized, publish aux to tracker. */
	for (i = 0; i < prog->aux->size_poke_tab; i++) {
		map_ptr = prog->aux->poke_tab[i].tail_call.map;
		if (!map_ptr->ops->map_poke_track ||
		    !map_ptr->ops->map_poke_untrack ||
		    !map_ptr->ops->map_poke_run) {
			verifier_bug(env, "poke tab is misconfigured");
			return -EFAULT;
		}

		ret = map_ptr->ops->map_poke_track(map_ptr, prog->aux);
		if (ret < 0) {
			verbose(env, "tracking tail call prog failed\n");
			return ret;
		}
	}

	return 0;
}

static struct bpf_prog *inline_bpf_loop(struct bpf_verifier_env *env,
					int position,
					s32 stack_base,
					u32 callback_subprogno,
					u32 *total_cnt)
{
	s32 r6_offset = stack_base + 0 * BPF_REG_SIZE;
	s32 r7_offset = stack_base + 1 * BPF_REG_SIZE;
	s32 r8_offset = stack_base + 2 * BPF_REG_SIZE;
	int reg_loop_max = BPF_REG_6;
	int reg_loop_cnt = BPF_REG_7;
	int reg_loop_ctx = BPF_REG_8;

	struct bpf_insn *insn_buf = env->insn_buf;
	struct bpf_prog *new_prog;
	u32 callback_start;
	u32 call_insn_offset;
	s32 callback_offset;
	u32 cnt = 0;

	/* This represents an inlined version of bpf_iter.c:bpf_loop,
	 * be careful to modify this code in sync.
	 */

	/* Return error and jump to the end of the patch if
	 * expected number of iterations is too big.
	 */
	insn_buf[cnt++] = BPF_JMP_IMM(BPF_JLE, BPF_REG_1, BPF_MAX_LOOPS, 2);
	insn_buf[cnt++] = BPF_MOV32_IMM(BPF_REG_0, -E2BIG);
	insn_buf[cnt++] = BPF_JMP_IMM(BPF_JA, 0, 0, 16);
	/* spill R6, R7, R8 to use these as loop vars */
	insn_buf[cnt++] = BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_6, r6_offset);
	insn_buf[cnt++] = BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_7, r7_offset);
	insn_buf[cnt++] = BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_8, r8_offset);
	/* initialize loop vars */
	insn_buf[cnt++] = BPF_MOV64_REG(reg_loop_max, BPF_REG_1);
	insn_buf[cnt++] = BPF_MOV32_IMM(reg_loop_cnt, 0);
	insn_buf[cnt++] = BPF_MOV64_REG(reg_loop_ctx, BPF_REG_3);
	/* loop header,
	 * if reg_loop_cnt >= reg_loop_max skip the loop body
	 */
	insn_buf[cnt++] = BPF_JMP_REG(BPF_JGE, reg_loop_cnt, reg_loop_max, 5);
	/* callback call,
	 * correct callback offset would be set after patching
	 */
	insn_buf[cnt++] = BPF_MOV64_REG(BPF_REG_1, reg_loop_cnt);
	insn_buf[cnt++] = BPF_MOV64_REG(BPF_REG_2, reg_loop_ctx);
	insn_buf[cnt++] = BPF_CALL_REL(0);
	/* increment loop counter */
	insn_buf[cnt++] = BPF_ALU64_IMM(BPF_ADD, reg_loop_cnt, 1);
	/* jump to loop header if callback returned 0 */
	insn_buf[cnt++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, -6);
	/* return value of bpf_loop,
	 * set R0 to the number of iterations
	 */
	insn_buf[cnt++] = BPF_MOV64_REG(BPF_REG_0, reg_loop_cnt);
	/* restore original values of R6, R7, R8 */
	insn_buf[cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_10, r6_offset);
	insn_buf[cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_10, r7_offset);
	insn_buf[cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_8, BPF_REG_10, r8_offset);

	*total_cnt = cnt;
	new_prog = bpf_patch_insn_data(env, position, insn_buf, cnt);
	if (!new_prog)
		return new_prog;

	/* callback start is known only after patching */
	callback_start = env->subprog_info[callback_subprogno].start;
	/* Note: insn_buf[12] is an offset of BPF_CALL_REL instruction */
	call_insn_offset = position + 12;
	callback_offset = callback_start - call_insn_offset - 1;
	new_prog->insnsi[call_insn_offset].imm = callback_offset;

	return new_prog;
}

static bool is_bpf_loop_call(struct bpf_insn *insn)
{
	return insn->code == (BPF_JMP | BPF_CALL) &&
		insn->src_reg == 0 &&
		insn->imm == BPF_FUNC_loop;
}

/* For all sub-programs in the program (including main) check
 * insn_aux_data to see if there are bpf_loop calls that require
 * inlining. If such calls are found the calls are replaced with a
 * sequence of instructions produced by `inline_bpf_loop` function and
 * subprog stack_depth is increased by the size of 3 registers.
 * This stack space is used to spill values of the R6, R7, R8.  These
 * registers are used to store the loop bound, counter and context
 * variables.
 */
int bpf_optimize_bpf_loop(struct bpf_verifier_env *env)
{
	struct bpf_subprog_info *subprogs = env->subprog_info;
	int i, cur_subprog = 0, cnt, delta = 0;
	struct bpf_insn *insn = env->prog->insnsi;
	int insn_cnt = env->prog->len;
	u16 stack_depth = subprogs[cur_subprog].stack_depth;
	u16 stack_depth_roundup = round_up(stack_depth, 8) - stack_depth;
	u16 stack_depth_extra = 0;

	for (i = 0; i < insn_cnt; i++, insn++) {
		struct bpf_loop_inline_state *inline_state =
			&env->insn_aux_data[i + delta].loop_inline_state;

		/* the callback that takes a stack in arena is not for a call from the program */
		if (is_bpf_loop_call(insn) && inline_state->fit_for_inline &&
		    !subprogs[inline_state->callback_subprogno].arena_stack_entry) {
			struct bpf_prog *new_prog;

			stack_depth_extra = BPF_REG_SIZE * 3 + stack_depth_roundup;
			new_prog = inline_bpf_loop(env,
						   i + delta,
						   -(stack_depth + stack_depth_extra),
						   inline_state->callback_subprogno,
						   &cnt);
			if (!new_prog)
				return -ENOMEM;

			delta     += cnt - 1;
			env->prog  = new_prog;
			insn       = new_prog->insnsi + i + delta;
		}

		if (subprogs[cur_subprog + 1].start == i + delta + 1) {
			subprogs[cur_subprog].stack_depth += stack_depth_extra;
			cur_subprog++;
			stack_depth = subprogs[cur_subprog].stack_depth;
			stack_depth_roundup = round_up(stack_depth, 8) - stack_depth;
			stack_depth_extra = 0;
		}
	}

	env->prog->aux->stack_depth = env->subprog_info[0].stack_depth;

	return 0;
}

/* Remove unnecessary spill/fill pairs, members of fastcall pattern,
 * adjust subprograms stack depth when possible.
 */
int bpf_remove_fastcall_spills_fills(struct bpf_verifier_env *env)
{
	struct bpf_subprog_info *subprog = env->subprog_info;
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	struct bpf_insn *insn = env->prog->insnsi;
	int insn_cnt = env->prog->len;
	u32 spills_num;
	bool modified = false;
	int i, j;

	for (i = 0; i < insn_cnt; i++, insn++) {
		if (aux[i].fastcall_spills_num > 0) {
			spills_num = aux[i].fastcall_spills_num;
			/* NOPs would be removed by opt_remove_nops() */
			for (j = 1; j <= spills_num; ++j) {
				*(insn - j) = NOP;
				*(insn + j) = NOP;
			}
			modified = true;
		}
		if ((subprog + 1)->start == i + 1) {
			if (modified && !subprog->keep_fastcall_stack)
				subprog->stack_depth = -subprog->fastcall_stack_off;
			subprog++;
			modified = false;
		}
	}

	return 0;
}
