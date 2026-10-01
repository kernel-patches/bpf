// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>
#include <linux/slab.h>
#include "exception.h"

#define verbose(env, fmt, args...) bpf_verifier_log_write(env, fmt, ##args)

#define MIN_BPF_CLEANUP_INFO_SIZE	12
#define MAX_CLEANUP_INFO_REC_SIZE	252	/* as MAX_FUNCINFO_REC_SIZE */

int bpf_exc_check_info(struct bpf_verifier_env *env, const union bpf_attr *attr,
		       bpfptr_t uattr)
{
	u32 krec_size = sizeof(struct bpf_cleanup_info);
	u32 i, nrec, urec_size, min_size, prev_end = 0;
	struct bpf_cleanup_info *krecord;
	bpfptr_t urecord;
	int ret = -EINVAL;

	nrec = attr->cleanup_info_cnt;
	if (!nrec)
		return 0;
	if (nrec > env->prog->len) {
		verbose(env, "cleanup info has %u records for %u instructions\n",
			nrec, env->prog->len);
		return -EINVAL;
	}

	urec_size = attr->cleanup_info_rec_size;
	if (urec_size < MIN_BPF_CLEANUP_INFO_SIZE ||
	    urec_size > MAX_CLEANUP_INFO_REC_SIZE ||
	    urec_size % sizeof(u32)) {
		verbose(env, "invalid cleanup info rec size %u\n", urec_size);
		return -EINVAL;
	}

	krecord = kvcalloc(nrec, krec_size, GFP_KERNEL_ACCOUNT | __GFP_NOWARN);
	if (!krecord)
		return -ENOMEM;

	min_size = min_t(u32, krec_size, urec_size);
	urecord = make_bpfptr(attr->cleanup_info, uattr.is_kernel);
	for (i = 0; i < nrec; i++) {
		struct bpf_subprog_info *sb, *se, *sl;
		struct bpf_cleanup_info *rec = &krecord[i];

		ret = bpf_check_uarg_tail_zero(urecord, krec_size, urec_size);
		if (ret) {
			if (ret == -E2BIG) {
				verbose(env, "nonzero tailing record in cleanup info\n");
				if (copy_to_bpfptr_offset(uattr,
							  offsetof(union bpf_attr,
								   cleanup_info_rec_size),
							  &min_size, sizeof(min_size)))
					ret = -EFAULT;
			}
			goto err_free;
		}

		if (copy_from_bpfptr(rec, urecord, min_size)) {
			ret = -EFAULT;
			goto err_free;
		}
		bpfptr_add(&urecord, urec_size);

		ret = -EINVAL;
		if (rec->begin_off >= rec->end_off) {
			verbose(env, "cleanup_info[%u]: begin %u >= end %u\n",
				i, rec->begin_off, rec->end_off);
			goto err_free;
		}
		if (i && rec->begin_off < prev_end) {
			verbose(env,
				"cleanup_info[%u]: range [%u,%u) is unsorted or overlaps the previous record\n",
				i, rec->begin_off, rec->end_off);
			goto err_free;
		}
		prev_end = rec->end_off;

		sb = bpf_find_containing_subprog(env, rec->begin_off);
		se = bpf_find_containing_subprog(env, rec->end_off - 1);
		sl = bpf_find_containing_subprog(env, rec->landing_pad_off);
		if (!sb || !se || !sl) {
			verbose(env, "cleanup_info[%u]: offset out of range\n", i);
			goto err_free;
		}
		if (sb != se || sb != sl) {
			verbose(env,
				"cleanup_info[%u]: range/landing pad span multiple subprogs\n",
				i);
			goto err_free;
		}
		/*
		 * A zero opcode is the second half of a 16-byte insn, not an
		 * insn. end_off is exclusive, so it may be one past the last.
		 */
		if (!env->prog->insnsi[rec->begin_off].code ||
		    !env->prog->insnsi[rec->landing_pad_off].code ||
		    (rec->end_off < env->prog->len &&
		     !env->prog->insnsi[rec->end_off].code)) {
			verbose(env, "cleanup_info[%u]: points at invalid insn\n", i);
			goto err_free;
		}
	}

	/* Reject a landing pad inside any call-site range, its own included. */
	ret = -EINVAL;
	for (i = 0; i < nrec; i++) {
		u32 pad = krecord[i].landing_pad_off;
		u32 l = 0, r = nrec;

		while (l < r) {
			u32 m = l + (r - l) / 2;

			if (pad < krecord[m].begin_off) {
				r = m;
			} else if (pad >= krecord[m].end_off) {
				l = m + 1;
			} else {
				verbose(env,
					"cleanup_info[%u]: landing pad %u is inside the call-site range of cleanup_info[%u]\n",
					i, pad, m);
				goto err_free;
			}
		}
	}

	env->cleanup_info = krecord;
	env->cleanup_info_cnt = nrec;
	return 0;

err_free:
	kvfree(krecord);
	return ret;
}

BTF_ID_LIST_SINGLE(bpf_unwind_id, func, bpf_unwind)
BTF_ID_LIST_SINGLE(bpf_unwind_resume_id, func, bpf_unwind_resume)

void bpf_exc_record_frame_entry(const struct bpf_verifier_state *state,
				struct bpf_func_state *frame, u32 id_gen)
{
	u32 i;

	frame->entry_active_locks = state->active_locks;
	frame->entry_preempt_locks = state->active_preempt_locks;
	frame->entry_rcu_locks = state->active_rcu_locks;
	frame->entry_irq_id = state->active_irq_id;

	/* Ids only ever go up, so this one tells the frame's own apart. */
	frame->entry_id_gen = id_gen;
	frame->entry_acquired_refs = 0;
	for (i = 0; i < state->acquired_refs; i++)
		if (state->refs[i].type == REF_TYPE_PTR)
			frame->entry_acquired_refs++;
}

int bpf_exc_check_frame_balance(struct bpf_verifier_env *env, const char *prefix)
{
	const struct bpf_verifier_state *state = env->cur_state;
	const struct bpf_func_state *frame = cur_func(env);
	u32 i, held;
	const char *what;

	if (state->active_rcu_locks != frame->entry_rcu_locks)
		what = "bpf_rcu_read_lock";
	else if (state->active_preempt_locks != frame->entry_preempt_locks)
		what = "bpf_preempt_disable";
	else if (state->active_irq_id != frame->entry_irq_id)
		what = "bpf_local_irq_save";
	else if (state->active_locks != frame->entry_active_locks)
		what = "bpf_spin_lock";
	else
		what = NULL;

	if (what) {
		verbose(env, "%s does not leave the frame's %s state as it found it\n",
			prefix, what);
		return -EINVAL;
	}

	/*
	 * References the same way. ids only go up, so entry_id_gen splits
	 * refs[] in two at frame entry: nothing above that line may still be
	 * held, and the count below it has to be what it was.
	 */
	for (i = 0, held = 0; i < state->acquired_refs; i++) {
		if (state->refs[i].type != REF_TYPE_PTR)
			continue;
		if (state->refs[i].id > frame->entry_id_gen) {
			verbose(env, "%s keeps the reference id=%d the frame acquired\n",
				prefix, state->refs[i].id);
			return -EINVAL;
		}
		held++;
	}
	if (held != frame->entry_acquired_refs) {
		verbose(env, "%s does not leave the frame's references as it found it\n",
			prefix);
		return -EINVAL;
	}

	return 0;
}

static int reject_throw(struct bpf_verifier_env *env)
{
	u32 i;

	for (i = 0; i < env->prog->len; i++) {
		if (!bpf_is_throw_kfunc(&env->prog->insnsi[i]))
			continue;
		verbose(env,
			"exception cleanup cannot be combined with bpf_throw at insn %u\n",
			i);
		return -EINVAL;
	}
	return 0;
}

static void mark_call_sites(struct bpf_verifier_env *env)
{
	u32 i, j;

	for (i = 0; i < env->cleanup_info_cnt; i++) {
		struct bpf_cleanup_info *rec = &env->cleanup_info[i];

		for (j = rec->begin_off; j < rec->end_off; j++) {
			struct bpf_insn *insn = &env->prog->insnsi[j];

			if (!bpf_pseudo_call(insn) && !bpf_is_callx(insn) &&
			    !bpf_is_unwind_kfunc(insn))
				continue;
			env->insn_aux_data[j].cleanup_pad = rec->landing_pad_off + 1;
		}
	}
}

bool bpf_prog_may_unwind(const struct bpf_verifier_env *env)
{
	u32 i;

	for (i = 0; i < env->subprog_cnt; i++)
		if (env->subprog_info[i].might_unwind)
			return true;
	return false;
}

int bpf_exc_check_prog(struct bpf_verifier_env *env)
{
	int err;

	if (bpf_prog_is_offloaded(env->prog->aux)) {
		verbose(env,
			"exception cleanup is not supported for offloaded programs\n");
		return -EINVAL;
	}
	if (!bpf_jit_supports_cleanup_pads() || !env->prog->jit_requested) {
		verbose(env,
			"exception cleanup needs a JIT that can dispatch landing pads\n");
		return -EOPNOTSUPP;
	}
	if (env->ops->gen_epilogue) {
		verbose(env,
			"exception cleanup is not supported for a program with an epilogue\n");
		return -EOPNOTSUPP;
	}
	if (env->exception_callback_subprog) {
		verbose(env,
			"exception cleanup cannot be combined with an exception callback\n");
		return -EINVAL;
	}
	err = reject_throw(env);
	if (err)
		return err;
	env->prog->jit_required = 1;
	return 0;
}

int bpf_exc_prepare(struct bpf_verifier_env *env)
{
	int err;

	if (!env->cleanup_info_cnt)
		return 0;

	err = bpf_exc_check_prog(env);
	if (err)
		return err;

	mark_call_sites(env);
	return 0;
}

bool bpf_is_unwind_kfunc(const struct bpf_insn *insn)
{
	return bpf_pseudo_kfunc_call(insn) && insn->off == 0 &&
	       insn->imm == bpf_unwind_id[0];
}

bool bpf_is_unwind_resume_kfunc(const struct bpf_insn *insn)
{
	return bpf_pseudo_kfunc_call(insn) && insn->off == 0 &&
	       insn->imm == bpf_unwind_resume_id[0];
}

int bpf_exc_pad_of_call(struct bpf_verifier_env *env, u32 idx)
{
	u32 pad = env->insn_aux_data[idx].cleanup_pad;

	return pad ? (int)pad - 1 : -1;
}
