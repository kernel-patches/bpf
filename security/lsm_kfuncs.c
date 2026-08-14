// SPDX-License-Identifier: GPL-2.0
/*
 * kfuncs exposing LSM interfaces to BPF programs.
 *
 * Copyright (C) 2026 Justin Suess
 */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/init.h>
#include <linux/security.h>

__bpf_kfunc_start_defs();

/**
 * bpf_security_locked_down - Call the security_locked_down() LSM hook
 * @what: lockdown reason to query
 *
 * Return: 0 if @what is not locked down, -EPERM if it is, or -EINVAL if
 * @what is outside (LOCKDOWN_NONE, LOCKDOWN_CONFIDENTIALITY_MAX).
 */
__bpf_kfunc int bpf_security_locked_down(enum lockdown_reason what)
{
	if (what <= LOCKDOWN_NONE || what >= LOCKDOWN_CONFIDENTIALITY_MAX)
		return -EINVAL;
	return security_locked_down(what);
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(lsm_kfunc_ids)
BTF_ID_FLAGS(func, bpf_security_locked_down)
BTF_KFUNCS_END(lsm_kfunc_ids)

#ifdef CONFIG_BPF_LSM
BTF_ID_LIST_SINGLE(lsm_locked_down_hook_id, func, bpf_lsm_locked_down)
#endif

static int lsm_kfunc_filter(const struct bpf_prog *prog, u32 kfunc_id)
{
	/* Filters run for every kfunc resolved through the hook. */
	if (!btf_id_set8_contains(&lsm_kfunc_ids, kfunc_id))
		return 0;

	/*
	 * Raw prog->type: keep out the rest of the shared tracing kfunc
	 * set (incl. perf/NMI) and extension programs.
	 */
	switch (prog->type) {
	case BPF_PROG_TYPE_SYSCALL:
		return 0;
#ifdef CONFIG_BPF_LSM
	case BPF_PROG_TYPE_LSM:
		/*
		 * A locked_down program calling this kfunc would recurse.
		 * Match on attach_btf_id: attach_func_name is not yet set
		 * when the filter runs from check_cfg.
		 */
		if (prog->aux->attach_btf_id == lsm_locked_down_hook_id[0])
			return -EACCES;
		return 0;
#endif
	default:
		return -EACCES;
	}
}

static const struct btf_kfunc_id_set lsm_kfunc_set = {
	.owner  = THIS_MODULE,
	.set    = &lsm_kfunc_ids,
	.filter = lsm_kfunc_filter,
};

static int __init lsm_kfuncs_init(void)
{
	int err;

	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_LSM, &lsm_kfunc_set);
	err = err ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &lsm_kfunc_set);
	if (err)
		pr_warn("lsm_kfuncs: kfunc registration failed: %d\n", err);
	return err;
}
late_initcall(lsm_kfuncs_init);
