// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>

#ifdef __x86_64__

#include <unistd.h>
#include <asm/ptrace.h>
#include "uprobe_syscall.skel.h"

extern int uprobe_syscall_arch(struct pt_regs *before, struct pt_regs *after);

static void test_uretprobe(void)
{
	struct pt_regs before = {}, after = {};
	unsigned long *pb = (unsigned long *) &before;
	unsigned long *pa = (unsigned long *) &after;
	unsigned long *prog_regs;
	struct uprobe_syscall *skel = NULL;
	unsigned int i, cnt;
	int err;

	skel = uprobe_syscall__open_and_load();
	if (!ASSERT_OK_PTR(skel, "uprobe_syscall__open_and_load"))
		goto cleanup;

	err = uprobe_syscall__attach(skel);
	if (!ASSERT_OK(err, "uprobe_syscall__attach"))
		goto cleanup;

	uprobe_syscall_arch(&before, &after);

	prog_regs = (unsigned long *) &skel->bss->regs;
	cnt = sizeof(before)/sizeof(*pb);

	for (i = 0; i < cnt; i++) {
		unsigned int offset = i * sizeof(unsigned long);

		/*
		 * Check register before and after uprobe_syscall_arch_test call
		 * that triggers the uretprobe.
		 */
		switch (offset) {
		case offsetof(struct pt_regs, rax):
			ASSERT_EQ(pa[i], 0xdeadbeef, "return value");
			break;
		default:
			if (!ASSERT_EQ(pb[i], pa[i], "register before-after value check"))
				fprintf(stdout, "failed register offset %u\n", offset);
		}

		/*
		 * Check register seen from bpf program and register after
		 * uprobe_syscall_arch_test call
		 */
		switch (offset) {
		/*
		 * These will be different (not set in uprobe_syscall_arch),
		 * we don't care.
		 */
		case offsetof(struct pt_regs, orig_rax):
		case offsetof(struct pt_regs, rip):
		case offsetof(struct pt_regs, cs):
		case offsetof(struct pt_regs, rsp):
		case offsetof(struct pt_regs, ss):
			break;
		default:
			if (!ASSERT_EQ(prog_regs[i], pa[i], "register prog-after value check"))
				fprintf(stdout, "failed register offset %u\n", offset);
		}
	}

cleanup:
	uprobe_syscall__destroy(skel);
}
#else
static void test_uretprobe(void) { }
#endif

void test_uprobe_syscall(void)
{
	if (test__start_subtest("uretprobe"))
		test_uretprobe();
}
