// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
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
