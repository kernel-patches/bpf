// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

SEC("fentry/bpf_fentry_test_sinfo")
__description("typedef: resolve")
__success __retval(0)
int BPF_PROG(resolve_typedef, struct skb_shared_info *si)
{
	volatile netmem_ref tmp __attribute__((unused)) = si->frags->netmem;

	return 0;
}

char _license[] SEC("license") = "GPL";
