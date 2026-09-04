// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

int data SEC(".percpu") = -1;
static const char fmt[] SEC(".percpu.fmt") = "data %d\n";

SEC("?kprobe")
__failure __msg("R{{[0-9]+}} points to percpu_array map which cannot be used as const string")
int verifier_strncmp(void *ctx)
{
	return bpf_strncmp("test", 5, fmt);
}

SEC("?kprobe")
__failure __msg("R{{[0-9]+}} points to percpu_array map which cannot be used as const string")
int verifier_snprintf(void *ctx)
{
	u64 args[] = { data };
	char buf[128];
	int len;

	len = bpf_snprintf(buf, sizeof(buf), fmt, args, sizeof(args));
	if (len > 0)
		bpf_printk("snprintf: %s\n", buf);
	return 0;
}

char _license[] SEC("license") = "GPL";
