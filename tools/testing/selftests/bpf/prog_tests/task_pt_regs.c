// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <test_progs.h>
#include <linux/ptrace.h>
#include "test_task_pt_regs.skel.h"

void test_task_pt_regs(void)
{
	int duration = 0;
	struct test_task_pt_regs *skel;
	struct bpf_link *uprobe_link;
	size_t uprobe_offset;
	ssize_t base_addr;
	bool match;

	base_addr = get_base_addr();
	if (CHECK(base_addr < 0, "get_base_addr",
		  "failed to find base addr: %zd", base_addr))
		return;
	uprobe_offset = get_uprobe_offset(&get_base_addr, base_addr);

	skel = test_task_pt_regs__open_and_load();
	if (CHECK(!skel, "skel_open", "failed to open skeleton\n"))
		return;
	if (CHECK(!skel->bss, "check_bss", ".bss wasn't mmap()-ed\n"))
		goto cleanup;

	uprobe_link = bpf_program__attach_uprobe(skel->progs.handle_uprobe,
						 false /* retprobe */,
						 0 /* self pid */,
						 "/proc/self/exe",
						 uprobe_offset);
	if (!ASSERT_OK_PTR(uprobe_link, "attach_uprobe"))
		goto cleanup;
	skel->links.handle_uprobe = uprobe_link;

	/* trigger & validate uprobe */
	get_base_addr();

	if (CHECK(skel->bss->uprobe_res != 1, "check_uprobe_res",
		  "wrong uprobe res: %d\n", skel->bss->uprobe_res))
		goto cleanup;

	match = !memcmp(&skel->bss->current_regs, &skel->bss->ctx_regs,
			sizeof(skel->bss->current_regs));
	CHECK(!match, "check_regs_match", "registers did not match");

cleanup:
	test_task_pt_regs__destroy(skel);
}
