// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2024 Yafang Shao <laoar.shao@gmail.com> */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf_misc.h"
#include "task_kfunc_common.h"

char _license[] SEC("license") = "GPL";

struct data_t {
	u64 a;
#if defined(__TARGET_ARCH_s390)
	/* It must be long-aligned on s390x */
	u64 b;
#else
	u32 b;
#endif
};
 
int bpf_iter_bits_new(struct bpf_iter_bits *it, const void *unsafe_ptr__ign,
		      u32 nr_bits) __ksym __weak;
int *bpf_iter_bits_next(struct bpf_iter_bits *it) __ksym __weak;
void bpf_iter_bits_destroy(struct bpf_iter_bits *it) __ksym __weak;

SEC("iter.s/cgroup")
__description("bits iter without destroy")
__failure __msg("Unreleased reference")
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
__description("bits iter with uninitialized iter in ->next()")
__failure __msg("expected an initialized iter_bits as arg #1")
int BPF_PROG(next_uninit, struct bpf_iter_meta *meta, struct cgroup *cgrp)
{
	struct bpf_iter_bits *it = NULL;

	bpf_iter_bits_next(it);
	return 0;
}

SEC("iter/cgroup")
__description("bits iter with uninitialized iter in ->destroy()")
__failure __msg("expected an initialized iter_bits as arg #1")
int BPF_PROG(destroy_uninit, struct bpf_iter_meta *meta, struct cgroup *cgrp)
{
	struct bpf_iter_bits it = {};

	bpf_iter_bits_destroy(&it);
	return 0;
}

#if !defined(__TARGET_ARCH_s390)
SEC("syscall")
__description("bits copy 32")
__success __retval(10)
int bits_copy32(void)
{
	/* It must be long-aligned on s390x */
	/* 21 bits:             --------------------- */
	u32 data = 0b11111101111101111100001000100101U;
	int nr = 0;
	int *bit;

	bpf_for_each(bits, bit, &data, 21)
		nr++;
	return nr;
}
#endif

SEC("syscall")
__description("bits copy 64")
__success __retval(18)
int bits_copy64(void)
{
	/* 34 bits:         ~-------- */
	u64 data = 0xffffefdf0f0f0f0fUL;
	int nr = 0;
	int *bit;

	bpf_for_each(bits, bit, &data, 34)
		nr++;
	return nr;
}

SEC("syscall")
__description("bits memalloc")
__success __retval(56)
int bits_memalloc(void)
{
	struct data_t data = {
		.a = 0xaaaaaaaaaaaaaaaaUL, /* 32 bits are set */
		.b = 0xbbbbbbbbU, /* 24 bits are set */
	};
	int nr = 0;
	int *bit;

	bpf_for_each(bits, bit, &data, 96)
		nr++;
	return nr;
}

SEC("syscall")
__description("bit index")
__success __retval(8)
int bit_index(void)
{
	u64 data = 0x100;
	int bit_idx = 0;
	int *bit;

	bpf_for_each(bits, bit, &data, 64) {
		if (*bit == 0)
			continue;
		bit_idx = *bit;
	}
	return bit_idx;
}
