// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "test_stack_var_off.skel.h"

int dummy;

noinline void uprobed_function(char *s, int len)
{
	/* Do something to keep the compiler from removing the function.
	 */
	dummy++;
}

void test_stack_var_off(void)
{
	int duration = 0;
	struct bpf_link *uprobe_link;
	struct test_stack_var_off *skel;
	size_t uprobe_offset;
	ssize_t base_addr;
	char s[100];

	base_addr = get_base_addr();
	if (CHECK(base_addr < 0, "get_base_addr",
		  "failed to find base addr: %zd", base_addr))
		return;
	uprobe_offset = (size_t)&uprobed_function - base_addr;

	skel = test_stack_var_off__open_and_load();
	if (CHECK(!skel, "skel_open", "failed to open skeleton\n"))
		return;
	if (CHECK(!skel->bss, "check_bss", ".bss wasn't mmap()-ed\n"))
		goto cleanup;

	uprobe_link = bpf_program__attach_uprobe(skel->progs.uprobe,
						 false /* retprobe */,
						 0 /* self pid */,
						 "/proc/self/exe",
						 uprobe_offset);
	if (CHECK(IS_ERR(uprobe_link), "attach_uprobe",
		  "err %ld\n", PTR_ERR(uprobe_link)))
		goto cleanup;
	skel->links.uprobe = uprobe_link;

	/* trigger uprobe */
	s[0] = 1;
	s[1] = 10;
	uprobed_function(&s[0], 2);

	if (CHECK(skel->bss->uprobe_res != 10, "check_uprobe_res",
		  "wrong uprobe res: %d\n", skel->bss->uprobe_res))
		goto cleanup;

cleanup:
	test_stack_var_off__destroy(skel);
}
