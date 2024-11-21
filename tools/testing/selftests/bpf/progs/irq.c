// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

SEC("?tc")
__failure __msg("BPF_EXIT instruction cannot be used inside bpf_local_irq_save-ed region")
int irq_restore_missing_1(struct __sk_buff *ctx)
{
	unsigned long flags;

	bpf_local_irq_save(&flags);
	return 0;
}

SEC("?tc")
__failure __msg("BPF_EXIT instruction cannot be used inside bpf_local_irq_save-ed region")
int irq_restore_missing_2(struct __sk_buff *ctx)
{
	unsigned long flags1;
	unsigned long flags2;

	bpf_local_irq_save(&flags1);
	bpf_local_irq_save(&flags2);
	return 0;
}

SEC("?tc")
__failure __msg("BPF_EXIT instruction cannot be used inside bpf_local_irq_save-ed region")
int irq_restore_missing_3(struct __sk_buff *ctx)
{
	unsigned long flags1;
	unsigned long flags2;
	unsigned long flags3;

	bpf_local_irq_save(&flags1);
	bpf_local_irq_save(&flags2);
	bpf_local_irq_save(&flags3);
	return 0;
}

SEC("?tc")
__failure __msg("BPF_EXIT instruction cannot be used inside bpf_local_irq_save-ed region")
int irq_restore_missing_3_minus_2(struct __sk_buff *ctx)
{
	unsigned long flags1;
	unsigned long flags2;
	unsigned long flags3;

	bpf_local_irq_save(&flags1);
	bpf_local_irq_save(&flags2);
	bpf_local_irq_save(&flags3);
	bpf_local_irq_restore(&flags3);
	bpf_local_irq_restore(&flags2);
	return 0;
}

static __noinline void local_irq_save(unsigned long *flags)
{
	bpf_local_irq_save(flags);
}

static __noinline void local_irq_restore(unsigned long *flags)
{
	bpf_local_irq_restore(flags);
}

SEC("?tc")
__failure __msg("BPF_EXIT instruction cannot be used inside bpf_local_irq_save-ed region")
int irq_restore_missing_1_subprog(struct __sk_buff *ctx)
{
	unsigned long flags;

	local_irq_save(&flags);
	return 0;
}

SEC("?tc")
__failure __msg("BPF_EXIT instruction cannot be used inside bpf_local_irq_save-ed region")
int irq_restore_missing_2_subprog(struct __sk_buff *ctx)
{
	unsigned long flags1;
	unsigned long flags2;

	local_irq_save(&flags1);
	local_irq_save(&flags2);
	return 0;
}

SEC("?tc")
__failure __msg("BPF_EXIT instruction cannot be used inside bpf_local_irq_save-ed region")
int irq_restore_missing_3_subprog(struct __sk_buff *ctx)
{
	unsigned long flags1;
	unsigned long flags2;
	unsigned long flags3;

	local_irq_save(&flags1);
	local_irq_save(&flags2);
	local_irq_save(&flags3);
	return 0;
}

SEC("?tc")
__failure __msg("BPF_EXIT instruction cannot be used inside bpf_local_irq_save-ed region")
int irq_restore_missing_3_minus_2_subprog(struct __sk_buff *ctx)
{
	unsigned long flags1;
	unsigned long flags2;
	unsigned long flags3;

	local_irq_save(&flags1);
	local_irq_save(&flags2);
	local_irq_save(&flags3);
	local_irq_restore(&flags3);
	local_irq_restore(&flags2);
	return 0;
}

SEC("?tc")
__success
int irq_balance(struct __sk_buff *ctx)
{
	unsigned long flags;

	local_irq_save(&flags);
	local_irq_restore(&flags);
	return 0;
}

SEC("?tc")
__success
int irq_balance_n(struct __sk_buff *ctx)
{
	unsigned long flags1;
	unsigned long flags2;
	unsigned long flags3;

	local_irq_save(&flags1);
	local_irq_save(&flags2);
	local_irq_save(&flags3);
	local_irq_restore(&flags3);
	local_irq_restore(&flags2);
	local_irq_restore(&flags1);
	return 0;
}

static __noinline void local_irq_balance(void)
{
	unsigned long flags;

	local_irq_save(&flags);
	local_irq_restore(&flags);
}

static __noinline void local_irq_balance_n(void)
{
	unsigned long flags1;
	unsigned long flags2;
	unsigned long flags3;

	local_irq_save(&flags1);
	local_irq_save(&flags2);
	local_irq_save(&flags3);
	local_irq_restore(&flags3);
	local_irq_restore(&flags2);
	local_irq_restore(&flags1);
}

SEC("?tc")
__success
int irq_balance_subprog(struct __sk_buff *ctx)
{
	local_irq_balance();
	return 0;
}

SEC("?tc")
__success
int irq_balance_n_subprog(struct __sk_buff *ctx)
{
	local_irq_balance_n();
	return 0;
}

SEC("?fentry.s/" SYS_PREFIX "sys_getpgid")
__failure __msg("sleepable helper bpf_copy_from_user#")
int irq_sleepable_helper(void *ctx)
{
	unsigned long flags;
	u32 data;

	local_irq_save(&flags);
	bpf_copy_from_user(&data, sizeof(data), NULL);
	local_irq_restore(&flags);
	return 0;
}

SEC("?fentry.s/" SYS_PREFIX "sys_getpgid")
__failure __msg("kernel func bpf_copy_from_user_str is sleepable within IRQ-disabled region")
int irq_sleepable_kfunc(void *ctx)
{
	unsigned long flags;
	u32 data;

	local_irq_save(&flags);
	bpf_copy_from_user_str(&data, sizeof(data), NULL, 0);
	local_irq_restore(&flags);
	return 0;
}

int __noinline global_local_irq_balance(void)
{
	local_irq_balance_n();
	return 0;
}

SEC("?tc")
__failure __msg("global function calls are not allowed with IRQs disabled")
int irq_global_subprog(struct __sk_buff *ctx)
{
	unsigned long flags;

	bpf_local_irq_save(&flags);
	global_local_irq_balance();
	bpf_local_irq_restore(&flags);
	return 0;
}

SEC("?tc")
__failure __msg("cannot restore irq state out of order")
int irq_restore_ooo(struct __sk_buff *ctx)
{
	unsigned long flags1;
	unsigned long flags2;

	bpf_local_irq_save(&flags1);
	bpf_local_irq_save(&flags2);
	bpf_local_irq_restore(&flags1);
	bpf_local_irq_restore(&flags2);
	return 0;
}

SEC("?tc")
__failure __msg("cannot restore irq state out of order")
int irq_restore_ooo_3(struct __sk_buff *ctx)
{
	unsigned long flags1;
	unsigned long flags2;
	unsigned long flags3;

	bpf_local_irq_save(&flags1);
	bpf_local_irq_save(&flags2);
	bpf_local_irq_restore(&flags2);
	bpf_local_irq_save(&flags3);
	bpf_local_irq_restore(&flags1);
	bpf_local_irq_restore(&flags3);
	return 0;
}

static __noinline void local_irq_save_3(unsigned long *flags1, unsigned long *flags2,
					unsigned long *flags3)
{
	local_irq_save(flags1);
	local_irq_save(flags2);
	local_irq_save(flags3);
}

SEC("?tc")
__success
int irq_restore_3_subprog(struct __sk_buff *ctx)
{
	unsigned long flags1;
	unsigned long flags2;
	unsigned long flags3;

	local_irq_save_3(&flags1, &flags2, &flags3);
	bpf_local_irq_restore(&flags3);
	bpf_local_irq_restore(&flags2);
	bpf_local_irq_restore(&flags1);
	return 0;
}

SEC("?tc")
__failure __msg("cannot restore irq state out of order")
int irq_restore_4_subprog(struct __sk_buff *ctx)
{
	unsigned long flags1;
	unsigned long flags2;
	unsigned long flags3;
	unsigned long flags4;

	local_irq_save_3(&flags1, &flags2, &flags3);
	bpf_local_irq_restore(&flags3);
	bpf_local_irq_save(&flags4);
	bpf_local_irq_restore(&flags4);
	bpf_local_irq_restore(&flags1);
	return 0;
}

SEC("?tc")
__failure __msg("cannot restore irq state out of order")
int irq_restore_ooo_3_subprog(struct __sk_buff *ctx)
{
	unsigned long flags1;
	unsigned long flags2;
	unsigned long flags3;

	local_irq_save_3(&flags1, &flags2, &flags3);
	bpf_local_irq_restore(&flags3);
	bpf_local_irq_restore(&flags2);
	bpf_local_irq_save(&flags3);
	bpf_local_irq_restore(&flags1);
	return 0;
}

SEC("?tc")
__failure __msg("expected an initialized")
int irq_restore_invalid(struct __sk_buff *ctx)
{
	unsigned long flags1;
	unsigned long flags = 0xfaceb00c;

	bpf_local_irq_save(&flags1);
	bpf_local_irq_restore(&flags);
	return 0;
}

SEC("?tc")
__failure __msg("expected uninitialized")
int irq_save_invalid(struct __sk_buff *ctx)
{
	unsigned long flags1;

	bpf_local_irq_save(&flags1);
	bpf_local_irq_save(&flags1);
	return 0;
}

SEC("?tc")
__failure __msg("expected an initialized")
int irq_restore_iter(struct __sk_buff *ctx)
{
	struct bpf_iter_num it;

	bpf_iter_num_new(&it, 0, 42);
	bpf_local_irq_restore((unsigned long *)&it);
	return 0;
}

SEC("?tc")
__failure __msg("Unreleased reference id=1")
int irq_save_iter(struct __sk_buff *ctx)
{
	struct bpf_iter_num it;

	/* Ensure same sized slot has st->ref_obj_id set, so we reject based on
	 * slot_type != STACK_IRQ_FLAG...
	 */
	_Static_assert(sizeof(it) == sizeof(unsigned long), "broken iterator size");

	bpf_iter_num_new(&it, 0, 42);
	bpf_local_irq_save((unsigned long *)&it);
	bpf_local_irq_restore((unsigned long *)&it);
	return 0;
}

SEC("?tc")
__failure __msg("expected an initialized")
int irq_flag_overwrite(struct __sk_buff *ctx)
{
	unsigned long flags;

	bpf_local_irq_save(&flags);
	flags = 0xdeadbeef;
	bpf_local_irq_restore(&flags);
	return 0;
}

SEC("?tc")
__failure __msg("expected an initialized")
int irq_flag_overwrite_partial(struct __sk_buff *ctx)
{
	unsigned long flags;

	bpf_local_irq_save(&flags);
	*(((char *)&flags) + 1) = 0xff;
	bpf_local_irq_restore(&flags);
	return 0;
}

char _license[] SEC("license") = "GPL";
