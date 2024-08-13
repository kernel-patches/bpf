// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../bpf_testmod/bpf_testmod.h"
#include "../bpf_testmod/bpf_testmod_kfunc.h"

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} epilogue_map SEC(".maps");

static __noinline int subprog(struct st_ops_args *args)
{
	args->a += 1;
	return 0;
}

SEC("struct_ops/test_prologue_subprog")
int BPF_PROG(test_prologue_subprog, struct st_ops_args *args)
{
	subprog(args);
	return 0;
}

SEC("struct_ops/test_epilogue_subprog")
int BPF_PROG(test_epilogue_subprog, struct st_ops_args *args)
{
	subprog(args);
	return 0;
}

SEC("struct_ops/test_pro_epilogue_subprog")
int BPF_PROG(test_pro_epilogue_subprog, struct st_ops_args *args)
{
	subprog(args);
	return 0;
}

SEC("struct_ops/test_prologue_kfunc")
int BPF_PROG(test_prologue_kfunc, struct st_ops_args *args)
{
	bpf_kfunc_st_ops_inc10(args);
	subprog(args);
	return 0;
}

SEC("struct_ops/test_epilogue_kfunc")
int BPF_PROG(test_epilogue_kfunc, struct st_ops_args *args)
{
	bpf_kfunc_st_ops_inc10(args);
	subprog(args);
	return 0;
}

SEC("struct_ops/test_pro_epilogue_kfunc")
int BPF_PROG(test_pro_epilogue_kfunc, struct st_ops_args *args)
{
	bpf_kfunc_st_ops_inc10(args);
	subprog(args);
	return 0;
}

SEC("struct_ops/test_epilogue_tail")
int test_epilogue_tail(unsigned long long *ctx)
{
	bpf_tail_call_static(ctx, &epilogue_map, 0);
	return 0;
}

SEC(".struct_ops.link")
struct bpf_testmod_st_ops pro_epilogue_subprog_ops = {
	.test_prologue = (void *)test_prologue_subprog,
	.test_epilogue = (void *)test_epilogue_subprog,
	.test_pro_epilogue = (void *)test_pro_epilogue_subprog,
};

SEC(".struct_ops.link")
struct bpf_testmod_st_ops pro_epilogue_kfunc_ops = {
	.test_prologue = (void *)test_prologue_kfunc,
	.test_epilogue = (void *)test_epilogue_kfunc,
	.test_pro_epilogue = (void *)test_pro_epilogue_kfunc,
};

SEC(".struct_ops.link")
struct bpf_testmod_st_ops pro_epilogue_tail_ops = {
	.test_prologue = (void *)test_prologue_subprog,
	.test_epilogue = (void *)test_epilogue_tail,
	.test_pro_epilogue = (void *)test_pro_epilogue_subprog,
};

SEC("syscall")
int syscall_prologue(struct st_ops_args *args)
{
	return bpf_kfunc_st_ops_test_prologue(args);
}

SEC("syscall")
int syscall_epilogue(struct st_ops_args *args)
{
	return bpf_kfunc_st_ops_test_epilogue(args);
}

SEC("syscall")
int syscall_pro_epilogue(struct st_ops_args *args)
{
	return bpf_kfunc_st_ops_test_pro_epilogue(args);
}
