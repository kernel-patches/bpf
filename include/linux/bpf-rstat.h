/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright 2022 Google LLC.
 */
#ifndef _BPF_RSTAT_H_
#define _BPF_RSTAT_H_

#include <linux/bpf.h>

#if defined(CONFIG_BPF_SYSCALL) && defined(CONFIG_CGROUPS)

int bpf_rstat_link_attach(const union bpf_attr *attr,
				 struct bpf_prog *prog);

void bpf_rstat_flush(struct cgroup *cgrp, int cpu);

#else /* defined(CONFIG_BPF_SYSCALL) && defined(CONFIG_CGROUPS) */

static inline int bpf_rstat_link_attach(const union bpf_attr *attr,
					struct bpf_prog *prog)
{
	return -ENOTSUPP;
}

static inline void bpf_rstat_flush(struct cgroup *cgrp, int cpu)
{
}

#endif /* defined(CONFIG_BPF_SYSCALL) && defined(CONFIG_CGROUPS) */

#endif  /* _BPF_RSTAT */
