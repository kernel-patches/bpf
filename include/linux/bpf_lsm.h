/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (C) 2020 Google LLC.
 */

#ifndef _LINUX_BPF_LSM_H
#define _LINUX_BPF_LSM_H

#include <linux/sched.h>
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/lsm_hooks.h>

#ifdef CONFIG_BPF_LSM

#define LSM_HOOK(RET, DEFAULT, NAME, ...) \
	RET bpf_lsm_##NAME(__VA_ARGS__);
#include <linux/lsm_hook_defs.h>
#undef LSM_HOOK

int bpf_lsm_verify_prog(struct bpf_verifier_log *vlog,
			const struct bpf_prog *prog);

bool bpf_lsm_is_sleepable_hook(u32 btf_id);
bool bpf_lsm_is_trusted(const struct bpf_prog *prog);

void bpf_lsm_find_cgroup_shim(const struct bpf_prog *prog, bpf_func_t *bpf_func);

int bpf_lsm_get_retval_range(const struct bpf_prog *prog,
			     struct bpf_retval_range *range);
#else /* !CONFIG_BPF_LSM */

static inline bool bpf_lsm_is_sleepable_hook(u32 btf_id)
{
	return false;
}

static inline bool bpf_lsm_is_trusted(const struct bpf_prog *prog)
{
	return false;
}

static inline int bpf_lsm_verify_prog(struct bpf_verifier_log *vlog,
				      const struct bpf_prog *prog)
{
	return -EOPNOTSUPP;
}

static inline void bpf_lsm_find_cgroup_shim(const struct bpf_prog *prog,
					   bpf_func_t *bpf_func)
{
}

static inline int bpf_lsm_get_retval_range(const struct bpf_prog *prog,
					   struct bpf_retval_range *range)
{
	return -EOPNOTSUPP;
}
#endif /* CONFIG_BPF_LSM */

#endif /* _LINUX_BPF_LSM_H */
