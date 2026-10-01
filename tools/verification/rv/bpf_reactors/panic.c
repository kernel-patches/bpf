// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

void bpf_rv_react(char *msg)
{
	struct pt_regs regs = { 0 };

	crash_kexec(&regs);
}

char LICENSE[] SEC("license") = "GPL";
static char DESCRIPTION[] SEC(".rodata.description") =
	"panic the system if an exception is found.";
