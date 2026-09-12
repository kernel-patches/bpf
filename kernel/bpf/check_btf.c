// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/filter.h>
#include <linux/btf.h>

#define verbose(env, fmt, args...) bpf_verifier_log_write(env, fmt, ##args)

static int check_abnormal_return(struct bpf_verifier_env *env)
{
	int i;

	for (i = 1; i < env->subprog_cnt; i++) {
		if (env->subprog_info[i].has_ld_abs) {
			verbose(env, "LD_ABS is not allowed in subprogs without BTF\n");
			return -EINVAL;
		}
		if (env->subprog_info[i].has_tail_call) {
			verbose(env, "tail_call is not allowed in subprogs without BTF\n");
			return -EINVAL;
		}
	}
	return 0;
}

/* The minimum supported BTF func info size */
#define MIN_BPF_FUNCINFO_SIZE	8
#define MAX_FUNCINFO_REC_SIZE	252

static int prepare_btf_func(struct bpf_verifier_env *env,
			    const union bpf_attr *attr,
			    bpfptr_t uattr)
{
	u32 krec_size = sizeof(struct bpf_func_info);
	const struct btf_type *type, *func_proto;
	u32 i, nfuncs, urec_size, min_size;
	struct bpf_func_info *krecord;
	struct bpf_prog *prog;
	const struct btf *btf;
	u32 prev_offset = 0;
	bpfptr_t urecord;
	int ret = -ENOMEM;

	nfuncs = attr->func_info_cnt;
	if (!nfuncs) {
		if (check_abnormal_return(env))
			return -EINVAL;
		return 0;
	}

	urec_size = attr->func_info_rec_size;
	if (urec_size < MIN_BPF_FUNCINFO_SIZE ||
	    urec_size > MAX_FUNCINFO_REC_SIZE ||
	    urec_size % sizeof(u32)) {
		verbose(env, "invalid func info rec size %u\n", urec_size);
		return -EINVAL;
	}

	prog = env->prog;
	btf = prog->aux->btf;

	urecord = make_bpfptr(attr->func_info, uattr.is_kernel);
	min_size = min_t(u32, krec_size, urec_size);

	krecord = kvcalloc(nfuncs, krec_size, GFP_KERNEL_ACCOUNT | __GFP_NOWARN);
	if (!krecord)
		return -ENOMEM;

	for (i = 0; i < nfuncs; i++) {
		ret = bpf_check_uarg_tail_zero(urecord, krec_size, urec_size);
		if (ret) {
			if (ret == -E2BIG) {
				verbose(env, "nonzero tailing record in func info");
				/* set the size kernel expects so loader can zero
				 * out the rest of the record.
				 */
				if (copy_to_bpfptr_offset(uattr,
							  offsetof(union bpf_attr, func_info_rec_size),
							  &min_size, sizeof(min_size)))
					ret = -EFAULT;
			}
			goto err_free;
		}

		if (copy_from_bpfptr(&krecord[i], urecord, min_size)) {
			ret = -EFAULT;
			goto err_free;
		}

		/* check insn_off */
		ret = -EINVAL;
		if (i == 0) {
			if (krecord[i].insn_off) {
				verbose(env,
					"nonzero insn_off %u for the first func info record",
					krecord[i].insn_off);
				goto err_free;
			}
		} else if (krecord[i].insn_off <= prev_offset) {
			verbose(env,
				"same or smaller insn offset (%u) than previous func info record (%u)",
				krecord[i].insn_off, prev_offset);
			goto err_free;
		}

		/* check type_id */
		type = btf_type_by_id(btf, krecord[i].type_id);
		if (!type || !btf_type_is_func(type)) {
			verbose(env, "invalid type id %d in func info",
				krecord[i].type_id);
			goto err_free;
		}

		func_proto = btf_type_by_id(btf, type->type);
		if (unlikely(!func_proto || !btf_type_is_func_proto(func_proto)))
			/* btf_func_check() already verified it during BTF load */
			goto err_free;

		prev_offset = krecord[i].insn_off;
		bpfptr_add(&urecord, urec_size);
	}

	prog->aux->func_info = krecord;
	prog->aux->func_info_cnt = nfuncs;
	return 0;

err_free:
	kvfree(krecord);
	return ret;
}

static int check_btf_func(struct bpf_verifier_env *env,
			  const union bpf_attr *attr,
			  bpfptr_t uattr)
{
	const struct btf_type *type, *func_proto, *ret_type;
	u32 i, nfuncs, urec_size;
	struct bpf_func_info *krecord;
	struct bpf_func_info_aux *info_aux = NULL;
	struct bpf_prog *prog;
	const struct btf *btf;
	bpfptr_t urecord;
	bool scalar_return;
	int ret = -ENOMEM;

	nfuncs = attr->func_info_cnt;
	if (!nfuncs) {
		if (check_abnormal_return(env))
			return -EINVAL;
		return 0;
	}
	if (nfuncs != env->subprog_cnt) {
		verbose(env, "number of funcs in func_info doesn't match number of subprogs\n");
		return -EINVAL;
	}

	urec_size = attr->func_info_rec_size;

	prog = env->prog;
	btf = prog->aux->btf;

	urecord = make_bpfptr(attr->func_info, uattr.is_kernel);

	krecord = prog->aux->func_info;
	info_aux = kzalloc_objs(*info_aux, nfuncs,
				GFP_KERNEL_ACCOUNT | __GFP_NOWARN);
	if (!info_aux)
		return -ENOMEM;

	for (i = 0; i < nfuncs; i++) {
		/* check insn_off */
		ret = -EINVAL;

		if (env->subprog_info[i].start != krecord[i].insn_off) {
			verbose(env, "func_info BTF section doesn't match subprog layout in BPF program\n");
			goto err_free;
		}

		/* Already checked type_id */
		type = btf_type_by_id(btf, krecord[i].type_id);
		info_aux[i].linkage = BTF_INFO_VLEN(type->info);
		/* Already checked func_proto */
		func_proto = btf_type_by_id(btf, type->type);

		ret_type = btf_type_skip_modifiers(btf, func_proto->type, NULL);
		scalar_return =
			btf_type_is_small_int(ret_type) || btf_is_any_enum(ret_type);
		if (i && !scalar_return && env->subprog_info[i].has_ld_abs) {
			verbose(env, "LD_ABS is only allowed in functions that return 'int'.\n");
			goto err_free;
		}
		if (i && !scalar_return && env->subprog_info[i].has_tail_call) {
			verbose(env, "tail_call is only allowed in functions that return 'int'.\n");
			goto err_free;
		}

		env->subprog_info[i].name = btf_name_by_offset(btf, type->name_off);
		bpfptr_add(&urecord, urec_size);
	}

	prog->aux->func_info_aux = info_aux;
	return 0;

err_free:
	kfree(info_aux);
	return ret;
}

#define MIN_BPF_LINEINFO_SIZE	offsetofend(struct bpf_line_info, line_col)
#define MAX_LINEINFO_REC_SIZE	MAX_FUNCINFO_REC_SIZE

static int check_btf_line(struct bpf_verifier_env *env,
			  const union bpf_attr *attr,
			  bpfptr_t uattr)
{
	u32 i, s, nr_linfo, ncopy, expected_size, rec_size, prev_offset = 0;
	struct bpf_subprog_info *sub;
	struct bpf_line_info *linfo;
	struct bpf_prog *prog;
	const struct btf *btf;
	bpfptr_t ulinfo;
	int err;

	nr_linfo = attr->line_info_cnt;
	if (!nr_linfo)
		return 0;
	if (nr_linfo > INT_MAX / sizeof(struct bpf_line_info))
		return -EINVAL;

	rec_size = attr->line_info_rec_size;
	if (rec_size < MIN_BPF_LINEINFO_SIZE ||
	    rec_size > MAX_LINEINFO_REC_SIZE ||
	    rec_size & (sizeof(u32) - 1))
		return -EINVAL;

	/* Need to zero it in case the userspace may
	 * pass in a smaller bpf_line_info object.
	 */
	linfo = kvzalloc_objs(struct bpf_line_info, nr_linfo,
			      GFP_KERNEL_ACCOUNT | __GFP_NOWARN);
	if (!linfo)
		return -ENOMEM;

	prog = env->prog;
	btf = prog->aux->btf;

	s = 0;
	sub = env->subprog_info;
	ulinfo = make_bpfptr(attr->line_info, uattr.is_kernel);
	expected_size = sizeof(struct bpf_line_info);
	ncopy = min_t(u32, expected_size, rec_size);
	for (i = 0; i < nr_linfo; i++) {
		err = bpf_check_uarg_tail_zero(ulinfo, expected_size, rec_size);
		if (err) {
			if (err == -E2BIG) {
				verbose(env, "nonzero tailing record in line_info");
				if (copy_to_bpfptr_offset(uattr,
							  offsetof(union bpf_attr, line_info_rec_size),
							  &expected_size, sizeof(expected_size)))
					err = -EFAULT;
			}
			goto err_free;
		}

		if (copy_from_bpfptr(&linfo[i], ulinfo, ncopy)) {
			err = -EFAULT;
			goto err_free;
		}

		/*
		 * Check insn_off to ensure
		 * 1) strictly increasing AND
		 * 2) bounded by prog->len
		 *
		 * The linfo[0].insn_off == 0 check logically falls into
		 * the later "missing bpf_line_info for func..." case
		 * because the first linfo[0].insn_off must be the
		 * first sub also and the first sub must have
		 * subprog_info[0].start == 0.
		 */
		if ((i && linfo[i].insn_off <= prev_offset) ||
		    linfo[i].insn_off >= prog->len) {
			verbose(env, "Invalid line_info[%u].insn_off:%u (prev_offset:%u prog->len:%u)\n",
				i, linfo[i].insn_off, prev_offset,
				prog->len);
			err = -EINVAL;
			goto err_free;
		}

		if (!prog->insnsi[linfo[i].insn_off].code) {
			verbose(env,
				"Invalid insn code at line_info[%u].insn_off\n",
				i);
			err = -EINVAL;
			goto err_free;
		}

		if (!btf_name_by_offset(btf, linfo[i].line_off) ||
		    !btf_name_by_offset(btf, linfo[i].file_name_off)) {
			verbose(env, "Invalid line_info[%u].line_off or .file_name_off\n", i);
			err = -EINVAL;
			goto err_free;
		}

		if (s != env->subprog_cnt) {
			if (linfo[i].insn_off == sub[s].start) {
				sub[s].linfo_idx = i;
				s++;
			} else if (sub[s].start < linfo[i].insn_off) {
				verbose(env, "missing bpf_line_info for func#%u\n", s);
				err = -EINVAL;
				goto err_free;
			}
		}

		prev_offset = linfo[i].insn_off;
		bpfptr_add(&ulinfo, rec_size);
	}

	if (s != env->subprog_cnt) {
		verbose(env, "missing bpf_line_info for %u funcs starting from func#%u\n",
			env->subprog_cnt - s, s);
		err = -EINVAL;
		goto err_free;
	}

	prog->aux->linfo = linfo;
	prog->aux->nr_linfo = nr_linfo;

	return 0;

err_free:
	kvfree(linfo);
	return err;
}

#define MIN_CORE_RELO_SIZE	sizeof(struct bpf_core_relo)
#define MAX_CORE_RELO_SIZE	MAX_FUNCINFO_REC_SIZE

static int check_core_relo(struct bpf_verifier_env *env,
			   const union bpf_attr *attr,
			   bpfptr_t uattr)
{
	u32 i, nr_core_relo, ncopy, expected_size, rec_size;
	struct bpf_core_relo core_relo = {};
	struct bpf_prog *prog = env->prog;
	const struct btf *btf = prog->aux->btf;
	struct bpf_core_ctx ctx = {
		.log = &env->log,
		.btf = btf,
	};
	bpfptr_t u_core_relo;
	int err;

	nr_core_relo = attr->core_relo_cnt;
	if (!nr_core_relo)
		return 0;
	if (nr_core_relo > INT_MAX / sizeof(struct bpf_core_relo))
		return -EINVAL;

	rec_size = attr->core_relo_rec_size;
	if (rec_size < MIN_CORE_RELO_SIZE ||
	    rec_size > MAX_CORE_RELO_SIZE ||
	    rec_size % sizeof(u32))
		return -EINVAL;

	u_core_relo = make_bpfptr(attr->core_relos, uattr.is_kernel);
	expected_size = sizeof(struct bpf_core_relo);
	ncopy = min_t(u32, expected_size, rec_size);

	/* Unlike func_info and line_info, copy and apply each CO-RE
	 * relocation record one at a time.
	 */
	for (i = 0; i < nr_core_relo; i++) {
		/* future proofing when sizeof(bpf_core_relo) changes */
		err = bpf_check_uarg_tail_zero(u_core_relo, expected_size, rec_size);
		if (err) {
			if (err == -E2BIG) {
				verbose(env, "nonzero tailing record in core_relo");
				if (copy_to_bpfptr_offset(uattr,
							  offsetof(union bpf_attr, core_relo_rec_size),
							  &expected_size, sizeof(expected_size)))
					err = -EFAULT;
			}
			break;
		}

		if (copy_from_bpfptr(&core_relo, u_core_relo, ncopy)) {
			err = -EFAULT;
			break;
		}

		if (core_relo.insn_off % 8 || core_relo.insn_off / 8 >= prog->len) {
			verbose(env, "Invalid core_relo[%u].insn_off:%u prog->len:%u\n",
				i, core_relo.insn_off, prog->len);
			err = -EINVAL;
			break;
		}

		err = bpf_core_apply(&ctx, &core_relo, i,
				     &prog->insnsi[core_relo.insn_off / 8]);
		if (err)
			break;
		bpfptr_add(&u_core_relo, rec_size);
	}
	return err;
}

static int cleanup_insn_subprog(struct bpf_verifier_env *env, u32 off)
{
	struct bpf_subprog_info *info;

	if (off >= env->prog->len)
		return -1;
	info = bpf_find_containing_subprog(env, off);
	return info ? info - env->subprog_info : -1;
}

#define MIN_BPF_CLEANUP_INFO_SIZE	12
#define MAX_CLEANUP_INFO_REC_SIZE	MAX_FUNCINFO_REC_SIZE

static int check_cleanup_info(struct bpf_verifier_env *env,
			      const union bpf_attr *attr,
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
	if (nrec > INT_MAX / krec_size)
		return -EINVAL;

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
		struct bpf_cleanup_info *rec = &krecord[i];
		int sb, se, sl;

		ret = bpf_check_uarg_tail_zero(urecord, krec_size, urec_size);
		if (ret) {
			if (ret == -E2BIG) {
				verbose(env, "nonzero tailing record in cleanup info\n");
				if (copy_to_bpfptr_offset(uattr,
							  offsetof(union bpf_attr, cleanup_info_rec_size),
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
			verbose(env, "cleanup_info[%u]: begin %u >= end %u\n", i, rec->begin_off, rec->end_off);
			goto err_free;
		}
		if (i && rec->begin_off < prev_end) {
			verbose(env,
				"cleanup_info[%u]: range [%u,%u) is unsorted or overlaps the previous record\n",
				i, rec->begin_off, rec->end_off);
			goto err_free;
		}
		prev_end = rec->end_off;

		sb = cleanup_insn_subprog(env, rec->begin_off);
		se = cleanup_insn_subprog(env, rec->end_off - 1);
		sl = cleanup_insn_subprog(env, rec->landing_pad_off);
		if (sb < 0 || se < 0 || sl < 0) {
			verbose(env, "cleanup_info[%u]: offset out of range\n", i);
			goto err_free;
		}
		if (sb != se || sb != sl) {
			verbose(env, "cleanup_info[%u]: range/landing pad span multiple subprogs\n", i);
			goto err_free;
		}
		/*
		 * The second half of a 16-byte instruction carries a zero
		 * opcode and is not an instruction of its own, so no offset
		 * may name one. end_off is exclusive, so it may also be one
		 * past the last instruction of the program.
		 */
		if (!env->prog->insnsi[rec->begin_off].code ||
		    !env->prog->insnsi[rec->landing_pad_off].code ||
		    (rec->end_off < env->prog->len &&
		     !env->prog->insnsi[rec->end_off].code)) {
			verbose(env, "cleanup_info[%u]: points at invalid insn\n", i);
			goto err_free;
		}
	}

	/*
	 * A landing pad may not lie inside a call-site range -- its own, which
	 * would have it unwind to itself, or any other record's.
	 *
	 * cleanup_paint_pads() marks the calls a range covers, so a pad that
	 * is also a covered call would be both at once: bpf_check_cfg() would
	 * grow an edge from one pad to another, and both the verifier's walk
	 * of the unwind and bpf_throw()'s would be told that an exception out
	 * of a pad transfers to a second pad -- while the first is already
	 * running with one in flight, which is the nested exception there is
	 * nowhere to put. Nothing emits this, because LLVM sinks a function's
	 * pads past every range it emits, and nothing here is prepared to run
	 * it.
	 *
	 * The ranges are sorted and do not overlap by now, so each pad is one
	 * binary search rather than a scan.
	 */
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

int bpf_prepare_btf_info(struct bpf_verifier_env *env,
			 const union bpf_attr *attr,
			 bpfptr_t uattr)
{
	struct btf *btf;
	int err;

	if (!attr->func_info_cnt && !attr->line_info_cnt) {
		if (check_abnormal_return(env))
			return -EINVAL;
		return 0;
	}

	btf = btf_get_by_fd(attr->prog_btf_fd);
	if (IS_ERR(btf))
		return PTR_ERR(btf);
	if (btf_is_kernel(btf)) {
		btf_put(btf);
		return -EACCES;
	}
	env->prog->aux->btf = btf;

	err = prepare_btf_func(env, attr, uattr);
	if (err)
		return err;
	return 0;
}

int bpf_check_btf_info(struct bpf_verifier_env *env,
		       const union bpf_attr *attr,
		       bpfptr_t uattr)
{
	int err;

	err = check_cleanup_info(env, attr, uattr);
	if (err)
		return err;

	if (!attr->func_info_cnt && !attr->line_info_cnt) {
		if (check_abnormal_return(env))
			return -EINVAL;
		return 0;
	}

	err = check_btf_func(env, attr, uattr);
	if (err)
		return err;

	err = check_btf_line(env, attr, uattr);
	if (err)
		return err;

	err = check_core_relo(env, attr, uattr);
	if (err)
		return err;

	return 0;
}
