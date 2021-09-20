// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include "test_ksyms_module_util.h"

KFUNC_KSYM_DECLARE_VALID_DISTINCT_256;
extern void bpf_testmod_test_mod_kfunc(int i) __ksym;

SEC("classifier")
int load(struct __sk_buff *skb)
{
	KFUNC_VALID_DISTINCT_256;
	KFUNC_VALID_SAME_ONE;
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
