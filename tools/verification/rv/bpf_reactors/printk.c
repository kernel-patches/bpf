// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

void bpf_rv_react(char *msg)
{
	bpf_printk("%s", msg);
}

char LICENSE[] SEC("license") = "GPL";
static char DESCRIPTION[] SEC(".rodata.description") =
	"prints the exception msg to the trace buffer.";
