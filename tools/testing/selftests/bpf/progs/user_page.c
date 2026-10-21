// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

#define USER_PAGE_ALLOC 1

int monitored_pid;
int action;
long user_addr;
unsigned long nr_pages;

SEC("uprobe.s//proc/self/exe:user_page_trigger")
int user_page_test(struct pt_regs *ctx)
{
	if ((bpf_get_current_pid_tgid() >> 32) != monitored_pid)
		return 0;

	switch (action) {
	case USER_PAGE_ALLOC:
		user_addr = bpf_user_page_alloc(nr_pages);
		break;
	}

	return 0;
}
