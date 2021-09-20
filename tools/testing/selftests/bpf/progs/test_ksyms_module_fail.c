// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

extern const int bpf_testmod_ksym_percpu __ksym;
extern void bpf_testmod_test_mod_kfunc(int i) __ksym;
extern void bpf_testmod_invalid_mod_kfunc(void) __ksym __weak;

int out_bpf_testmod_ksym = 0;
const volatile int x = 0;

SEC("classifier")
int load(struct __sk_buff *skb)
{
	/* This should be preserved by clang, but not DCE'd by verifier,
	 * hence fail loading
	 */
	if (!x) {
		bpf_testmod_invalid_mod_kfunc();
		return -1;
	}
	bpf_testmod_test_mod_kfunc(42);
	out_bpf_testmod_ksym = *(int *)bpf_this_cpu_ptr(&bpf_testmod_ksym_percpu);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
