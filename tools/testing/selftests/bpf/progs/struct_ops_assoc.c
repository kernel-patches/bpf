// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"
#include "../test_kmods/bpf_testmod.h"
#include "../test_kmods/bpf_testmod_kfunc.h"

char _license[] SEC("license") = "GPL";

int test_pid;

/* Programs associated with st_ops_map_a */

#define MAP_A_MAGIC 1234
int test_err_a;

SEC("struct_ops")
int BPF_PROG(test_1_a, struct st_ops_args *args)
{
	return MAP_A_MAGIC;
}

SEC("tp_btf/sys_enter")
int BPF_PROG(sys_enter_prog_a, struct pt_regs *regs, long id)
{
	struct st_ops_args args = {};
	struct task_struct *task;
	int ret;

	task = bpf_get_current_task_btf();
	if (!test_pid || task->pid != test_pid)
		return 0;

	ret = bpf_kfunc_multi_st_ops_test_1_assoc(&args);
	if (ret != MAP_A_MAGIC)
		test_err_a++;

	return 0;
}

SEC("syscall")
int syscall_prog_a(void *ctx)
{
	struct st_ops_args args = {};
	int ret;

	ret = bpf_kfunc_multi_st_ops_test_1_assoc(&args);
	if (ret != MAP_A_MAGIC)
		test_err_a++;

	return 0;
}

SEC(".struct_ops.link")
struct bpf_testmod_multi_st_ops st_ops_map_a = {
	.test_1 = (void *)test_1_a,
};

/* Programs associated with st_ops_map_b */

#define MAP_B_MAGIC 5678
int test_err_b;

SEC("struct_ops")
int BPF_PROG(test_1_b, struct st_ops_args *args)
{
	return MAP_B_MAGIC;
}

SEC("tp_btf/sys_enter")
int BPF_PROG(sys_enter_prog_b, struct pt_regs *regs, long id)
{
	struct st_ops_args args = {};
	struct task_struct *task;
	int ret;

	task = bpf_get_current_task_btf();
	if (!test_pid || task->pid != test_pid)
		return 0;

	ret = bpf_kfunc_multi_st_ops_test_1_assoc(&args);
	if (ret != MAP_B_MAGIC)
		test_err_b++;

	return 0;
}

SEC("syscall")
int syscall_prog_b(void *ctx)
{
	struct st_ops_args args = {};
	int ret;

	ret = bpf_kfunc_multi_st_ops_test_1_assoc(&args);
	if (ret != MAP_B_MAGIC)
		test_err_b++;

	return 0;
}

SEC(".struct_ops.link")
struct bpf_testmod_multi_st_ops st_ops_map_b = {
	.test_1 = (void *)test_1_b,
};

/* Test for aux injection with stale register contamination.
 *
 * This test reproduces the scenario where the BPF verifier fails to
 * inject the implicit bpf_prog_aux pointer for kfuncs with
 * KF_IMPLICIT_ARGS.  The program uses inline assembly to explicitly
 * set R2 (the register for the 2nd kfunc argument, which maps to
 * the implicit bpf_prog_aux *) to a known magic value (0xDEAD,
 * chosen with bit 31 clear to avoid BPF ALU64 sign-extension):
 *
 *   asm volatile("r2 = %[magic]" :: [magic] "ri"(0xDEAD) : "r2");
 *
 * Then bpf_kfunc_aux_inject_stale() is called.  The kernel verifier
 * should inject the real bpf_prog_aux into R2, overriding the magic
 * value.  The kfunc compares aux against 0xDEAD:
 *
 *   - aux == 0xDEAD  → kernel failed to inject aux → test fails
 *   - aux != 0xDEAD  → kernel correctly injected aux → test passes
 */
int test_err_inject;

SEC("tp_btf/sys_enter")
int BPF_PROG(sys_enter_prog_test_aux_inject, struct pt_regs *regs, long id)
{
	struct task_struct *task;
	int marker = 0x5A5A;
	int ret;

	task = bpf_get_current_task_btf();
	if (!test_pid || task->pid != test_pid)
		return 0;

	asm volatile("r2 = %[magic]" :: [magic] "ri"(0xDEAD) : "r2");

	ret = bpf_kfunc_aux_inject_stale(marker);
	if (ret != marker)
		test_err_inject++;

	return 0;
}
