// SPDX-License-Identifier: GPL-2.0
/* Copyright 2022 Sony Group Corporation */
#include <sys/prctl.h>
#include <test_progs.h>
#include "test_bpf_syscall_macro.skel.h"

void serial_test_bpf_syscall_macro(void)
{
	struct test_bpf_syscall_macro *skel = NULL;
	int err;
	int duration = 0;
	int exp_arg1 = 1001;
	unsigned long exp_arg2 = 12;
	unsigned long exp_arg3 = 13;
	unsigned long exp_arg4 = 14;
	unsigned long exp_arg5 = 15;

	/* check whether it can load program */
	skel = test_bpf_syscall_macro__open_and_load();
	if (CHECK(!skel, "skel_open_and_load", "skeleton open_and_load failed\n"))
		goto cleanup;

	/* check whether it can attach kprobe */
	err = test_bpf_syscall_macro__attach(skel);
	if (CHECK(err, "attach_kprobe", "err %d\n", err))
		goto cleanup;

	/* check whether args of syscall are copied correctly */
	prctl(exp_arg1, exp_arg2, exp_arg3, exp_arg4, exp_arg5);
	if (CHECK(skel->bss->arg1 != exp_arg1, "syscall_arg1",
		  "exp %d, got %d\n", exp_arg1, skel->bss->arg1)) {
		goto cleanup;
	}
	if (CHECK(skel->bss->arg2 != exp_arg2, "syscall_arg2",
		  "exp %ld, got %ld\n", exp_arg2, skel->bss->arg2)) {
		goto cleanup;
	}
	if (CHECK(skel->bss->arg3 != exp_arg3, "syscall_arg3",
		  "exp %ld, got %ld\n", exp_arg3, skel->bss->arg3)) {
		goto cleanup;
	}
	/* it cannot copy arg4 when uses PT_REGS_PARM4 on x86_64 */
#ifdef __x86_64__
	if (CHECK(skel->bss->arg4_cx == exp_arg4, "syscall_arg4_from_cx",
		  "exp %ld, got %ld\n", exp_arg4, skel->bss->arg4_cx)) {
		goto cleanup;
	}
#endif
	if (CHECK(skel->bss->arg4 != exp_arg4, "syscall_arg4",
		  "exp %ld, got %ld\n", exp_arg4, skel->bss->arg4)) {
		goto cleanup;
	}
	if (CHECK(skel->bss->arg5 != exp_arg5, "syscall_arg5",
		  "exp %ld, got %ld\n", exp_arg5, skel->bss->arg5)) {
		goto cleanup;
	}

cleanup:
	test_bpf_syscall_macro__destroy(skel);
}
