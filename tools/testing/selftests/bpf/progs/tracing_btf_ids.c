// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

SEC("fentry/migrate_disable")
__failure __msg("Attaching tracing to __btf_id function 'migrate_disable' is rejected.")
int BPF_PROG(btf_ids)
{
	return 0;
}
