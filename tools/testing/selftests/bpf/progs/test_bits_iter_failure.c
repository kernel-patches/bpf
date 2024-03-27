// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2024 Yafang Shao <laoar.shao@gmail.com> */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf_misc.h"
#include "task_kfunc_common.h"

char _license[] SEC("license") = "GPL";

int bpf_iter_bits_new(struct bpf_iter_bits *it, const void *unsafe_ptr__ign,
		      u32 nr_bits) __ksym __weak;
int *bpf_iter_bits_next(struct bpf_iter_bits *it) __ksym __weak;
void bpf_iter_bits_destroy(struct bpf_iter_bits *it) __ksym __weak;

SEC("iter.s/cgroup")
__failure __msg("Unreleased reference id=3 alloc_insn=10")
int BPF_PROG(no_destroy, struct bpf_iter_meta *meta, struct cgroup *cgrp)
{
	struct bpf_iter_bits it;
	struct task_struct *p;

	p = bpf_task_from_pid(1);
	if (!p)
		return 1;

	bpf_iter_bits_new(&it, p->cpus_ptr, 8192);

	bpf_iter_bits_next(&it);
	bpf_task_release(p);
	return 0;
}

SEC("iter/cgroup")
__failure __msg("expected an initialized iter_bits as arg #1")
int BPF_PROG(next_uninit, struct bpf_iter_meta *meta, struct cgroup *cgrp)
{
	struct bpf_iter_bits *it = NULL;

	bpf_iter_bits_next(it);
	return 0;
}

SEC("iter/cgroup")
__failure __msg("expected an initialized iter_bits as arg #1")
int BPF_PROG(destroy_uninit, struct bpf_iter_meta *meta, struct cgroup *cgrp)
{
	struct bpf_iter_bits it = {};

	bpf_iter_bits_destroy(&it);
	return 0;
}
