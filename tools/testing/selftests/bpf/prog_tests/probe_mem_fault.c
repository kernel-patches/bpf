// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <test_progs.h>
#include "probe_mem_fault.skel.h"

#if defined(__x86_64__)
#include <asm/vsyscall.h>
#endif

/*
 * Addresses a PROBE_MEM load has to survive. Either the JIT's address check
 * or the fault handler must turn each load into a zero result. The user and
 * guard page addresses are those of x86-64 with four and five paging levels;
 * on other kernels they are merely unmapped.
 */
static const struct {
	const char *name;
	__u64 addr;
} bad_addrs[] = {
#if !defined(__s390x__)
	/* s390x has its lowcore at these addresses, so the loads read it. */
	{ "null", 0 },
	{ "low_user", 4096 },
#endif
	{ "last_user_page_4l", (1ULL << 47) - 2 * 4096 },
	{ "guard_page_4l", (1ULL << 47) - 4096 },
	{ "last_user_page_5l", (1ULL << 56) - 2 * 4096 },
	{ "guard_page_5l", (1ULL << 56) - 4096 },
	{ "non_canonical", 1ULL << 63 },
#if defined(__x86_64__)
	{ "vsyscall", VSYSCALL_ADDR },
	{ "vsyscall_tail", VSYSCALL_ADDR + 0x800 },
#endif
};

static void trigger(struct probe_mem_fault *skel, int *runs)
{
	skel->bss->val_dw = ~0ULL;
	skel->bss->val_w = ~0U;
	skel->bss->val_b = ~0;
	usleep(1);
	ASSERT_EQ(skel->bss->runs, ++*runs, "runs");
}

void test_probe_mem_fault(void)
{
	struct probe_mem_fault *skel;
	int runs = 0, i;

	skel = probe_mem_fault__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	skel->bss->target_pid = getpid();
	if (!ASSERT_OK(probe_mem_fault__attach(skel), "attach"))
		goto out;

	/* A valid kernel address is read for real. */
	skel->bss->use_current_task = true;
	trigger(skel, &runs);
	ASSERT_EQ(skel->bss->val_w, getpid(), "pid");
	ASSERT_NEQ(skel->bss->val_dw, 0, "start_time");
	ASSERT_NEQ(skel->bss->val_b, 0, "comm");

	skel->bss->use_current_task = false;
	for (i = 0; i < ARRAY_SIZE(bad_addrs); i++) {
		if (!test__start_subtest(bad_addrs[i].name))
			continue;
		skel->bss->addr = bad_addrs[i].addr;
		trigger(skel, &runs);
		ASSERT_EQ(skel->bss->val_dw, 0, "start_time");
		ASSERT_EQ(skel->bss->val_w, 0, "pid");
		ASSERT_EQ(skel->bss->val_b, 0, "comm");
	}
out:
	probe_mem_fault__destroy(skel);
}
