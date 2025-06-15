// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bpf_misc.h"

__u64 in_user;
__u64 ret_user;

struct simple_ctx {
	__u64 x;
};

SEC("syscall")
int simple_test(struct simple_ctx *ctx)
{
	switch (ctx->x) {
	case 0:
		bpf_printk("%lu\n", ctx->x + 1);
		ret_user = 2;
		break;
	case 1:
		bpf_printk("%lu\n", ctx->x + 7);
		ret_user = 3;
		break;
	case 2:
		bpf_printk("%lu\n", ctx->x + 9);
		ret_user = 4;
		break;
	case 3:
		bpf_printk("%lu\n", ctx->x + 11);
		ret_user = 5;
		break;
	case 4:
		bpf_printk("%lu\n", ctx->x + 17);
		ret_user = 7;
		break;
	default:
		bpf_printk("%lu\n", ctx->x + 177);
		ret_user = 19;
		break;
	}

	return 0;
}

SEC("syscall")
int simple_test2(struct simple_ctx *ctx)
{
	switch (ctx->x) {
	case 0:
		bpf_printk("%lu\n", ctx->x + 1);
		ret_user = 2;
		break;
	case 1:
		bpf_printk("%lu\n", ctx->x + 7);
		ret_user = 3;
		break;
	case 2:
		bpf_printk("%lu\n", ctx->x + 9);
		ret_user = 4;
		break;
	case 3:
		bpf_printk("%lu\n", ctx->x + 11);
		ret_user = 5;
		break;
	case 4:
		bpf_printk("%lu\n", ctx->x + 17);
		ret_user = 7;
		break;
	default:
		bpf_printk("%lu\n", ctx->x + 177);
		ret_user = 19;
		break;
	}

	return 0;
}

SEC("fentry/" SYS_PREFIX "sys_nanosleep")
int simple_test_other_sec(struct pt_regs *ctx)
{
	__u64 x = in_user;

	switch (x) {
	case 0:
		bpf_printk("%lu\n", x + 1);
		ret_user = 2;
		break;
	case 1:
		bpf_printk("%lu\n", x + 7);
		ret_user = 3;
		break;
	case 2:
		bpf_printk("%lu\n", x + 9);
		ret_user = 4;
		break;
	case 3:
		bpf_printk("%lu\n", x + 11);
		ret_user = 5;
		break;
	case 4:
		bpf_printk("%lu\n", x + 17);
		ret_user = 7;
		break;
	default:
		bpf_printk("%lu\n", x + 177);
		ret_user = 19;
		break;
	}

	return 0;
}

SEC("syscall")
int two_towers(struct simple_ctx *ctx)
{
	switch (ctx->x) {
	case 0:
		bpf_printk("%lu\n", ctx->x + 1);
		ret_user = 2;
		break;
	case 1:
		bpf_printk("%lu\n", ctx->x + 7);
		ret_user = 3;
		break;
	case 2:
		bpf_printk("%lu\n", ctx->x + 9);
		ret_user = 4;
		break;
	case 3:
		bpf_printk("%lu\n", ctx->x + 11);
		ret_user = 5;
		break;
	case 4:
		bpf_printk("%lu\n", ctx->x + 17);
		ret_user = 7;
		break;
	default:
		bpf_printk("%lu\n", ctx->x + 177);
		ret_user = 19;
		break;
	}

	switch (ctx->x + !!ret_user) {
	case 0: /* never happens */
		bpf_printk("%lu\n", ctx->x + 1);
		ret_user = 102;
		break;
	case 1:
		bpf_printk("%lu\n", ctx->x + 7);
		ret_user = 103;
		break;
	case 2:
		bpf_printk("%lu\n", ctx->x + 9);
		ret_user = 104;
		break;
	case 3:
		bpf_printk("%lu\n", ctx->x + 11);
		ret_user = 107;
		break;
	case 4:
		bpf_printk("%lu\n", ctx->x + 11);
		ret_user = 205;
		break;
	case 5:
		bpf_printk("%lu\n", ctx->x + 11);
		ret_user = 115;
		break;
	default:
		bpf_printk("%lu\n", ctx->x + 177);
		ret_user = 1019;
		break;
	}

	return 0;
}

/* this actually creates a big insn_set map */
SEC("syscall")
int the_return_of_the_king(struct simple_ctx *ctx)
{
	switch (ctx->x) {
	case 0:
		bpf_printk("%lu\n", ctx->x + 1);
		ret_user = 2;
		break;
	case 11:
		bpf_printk("%lu\n", ctx->x + 7);
		ret_user = 3;
		break;
	case 27:
		bpf_printk("%lu\n", ctx->x + 9);
		ret_user = 4;
		break;
	case 31:
		bpf_printk("%lu\n", ctx->x + 11);
		ret_user = 5;
		break;
	case 447:
		bpf_printk("%lu\n", ctx->x + 17);
		ret_user = 7;
		break;
	default:
		bpf_printk("%lu\n", ctx->x + 177);
		ret_user = 19;
		break;
	}

	return 0;
}

/* Just to introduce some non-zero offsets in .text */
static __noinline int i_am_a_little_tiny_foo(volatile struct simple_ctx *ctx __arg_ctx)
{
	if (ctx)
		return 1;
	else
		return 13;
}

SEC("syscall") int just_me(struct simple_ctx *ctx)
{
	ret_user = 0;
	return i_am_a_little_tiny_foo(ctx);
}

static __noinline int __static_global(__u64 x)
{
	switch (x) {
	case 0:
		bpf_printk("%lu\n", x + 1);
		ret_user = 2;
		break;
	case 1:
		bpf_printk("%lu\n", x + 7);
		ret_user = 3;
		break;
	case 2:
		bpf_printk("%lu\n", x + 9);
		ret_user = 4;
		break;
	case 3:
		bpf_printk("%lu\n", x + 11);
		ret_user = 5;
		break;
	case 4:
		bpf_printk("%lu\n", x + 17);
		ret_user = 7;
		break;
	default:
		bpf_printk("%lu\n", x + 177);
		ret_user = 19;
		break;
	}

	return 0;
}

SEC("syscall")
int use_static_global1(struct simple_ctx *ctx)
{
	ret_user = 0;
	return __static_global(ctx->x);
}

SEC("syscall")
int use_static_global2(struct simple_ctx *ctx)
{
	ret_user = 0;
	bpf_printk("%lu\n", ctx->x + 1);
	return __static_global(ctx->x);
}

SEC("fentry/" SYS_PREFIX "sys_nanosleep")
int use_static_global_other_sec(void *ctx)
{
	return __static_global(in_user);
}

__noinline int __gobble_till_you_global(__u64 x)
{
	switch (x) {
	case 0:
		bpf_printk("%lu\n", x + 1);
		ret_user = 2;
		break;
	case 1:
		bpf_printk("%lu\n", x + 7);
		ret_user = 3;
		break;
	case 2:
		bpf_printk("%lu\n", x + 9);
		ret_user = 4;
		break;
	case 3:
		bpf_printk("%lu\n", x + 11);
		ret_user = 5;
		break;
	case 4:
		bpf_printk("%lu\n", x + 17);
		ret_user = 7;
		break;
	default:
		bpf_printk("%lu\n", x + 177);
		ret_user = 19;
		break;
	}

	return 0;
}

SEC("syscall")
int use_nonstatic_global1(struct simple_ctx *ctx)
{
	ret_user = 0;
	return __gobble_till_you_global(ctx->x);
}

SEC("syscall")
int use_nonstatic_global2(struct simple_ctx *ctx)
{
	ret_user = 0;
	bpf_printk("%lu\n", ctx->x + 1);
	return __gobble_till_you_global(ctx->x);
}

SEC("fentry/" SYS_PREFIX "sys_nanosleep")
int use_nonstatic_global_other_sec(void *ctx)
{
	return __gobble_till_you_global(in_user);
}

char _license[] SEC("license") = "GPL";
