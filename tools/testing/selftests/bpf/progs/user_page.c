// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

#define USER_PAGE_ALLOC 1
#define USER_PAGE_EXEC 2
#define USER_PAGE_EXEC_ONLY 3

int monitored_pid;
int action;
long user_addr;
long exec_addr;
unsigned long nr_pages;
int write_ret;
int exec_ret;
static const unsigned char insns[] = {
	0xf3, 0x0f, 0x1e, 0xfa, /* endbr64 */
	0xb8, 42, 0, 0, 0, 0xc3, /* mov $42, %eax; ret */
};

SEC("uprobe.s//proc/self/exe:user_page_trigger")
int user_page_test(struct pt_regs *ctx)
{
	if ((bpf_get_current_pid_tgid() >> 32) != monitored_pid)
		return 0;

	switch (action) {
	case USER_PAGE_ALLOC:
		user_addr = bpf_user_page_alloc(nr_pages);
		break;
	case USER_PAGE_EXEC:
		write_ret = bpf_probe_write_user_faultable((void *)exec_addr,
							   insns, sizeof(insns));
		exec_ret = write_ret ? write_ret :
			bpf_user_page_exec(exec_addr);
		break;
	case USER_PAGE_EXEC_ONLY:
		exec_ret = bpf_user_page_exec(exec_addr);
		break;
	}

	return 0;
}
