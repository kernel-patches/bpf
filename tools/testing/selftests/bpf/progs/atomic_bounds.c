// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("fentry/bpf_fentry_test1")
int BPF_PROG(sub, int x)
{
	int a = 0;
	int b = __sync_fetch_and_add(&a, 1);
	/* b is certainly 0 here. Can the verifier tell? */
	while (b)
		continue;
	return 0;
}
