// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "exceptions_cleanup.h"

__u64 ext_pad_ran = 0;

/* Without a 32-bit int in BTF, libbpf's dummy_ksym var gets type id 0. */
int btf_int_anchor;

static __used __noinline void __kfunc_btf_anchor(void)
{
	bpf_throw(0);
	bpf_preempt_disable();
	bpf_preempt_enable();
	bpf_unwind_resume();
}

static __used __naked __noinline __u64 ext_frame(void)
{
	asm volatile (
	"call bpf_preempt_disable;"
	"r1 = %[cookie];"
"1:"	"call bpf_throw;"		/* cleanup region */
"2:"
	"exit;"
"3:"					/* landing pad */
	"call bpf_preempt_enable;"
	"r1 = %[ext_pad_ran] ll;"
	"r2 = 1;"
	"*(u64 *)(r1 + 0) = r2;"
	"call bpf_unwind_resume;"
	"exit;"
	CLEANUP_REC("1b", "2b", "3b")
	:
	: [cookie]"i"(THROW_COOKIE), __imm_addr(ext_pad_ran)
	: __clobber_all);
}

SEC("freplace/fr_callee")
__u64 new_fr_callee(__u64 x)
{
	return ext_frame();
}

char _license[] SEC("license") = "GPL";
