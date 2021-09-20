// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include "test_ksyms_module_util.h"

KFUNC_KSYM_DECLARE_VALID_DISTINCT_256;
extern const int bpf_testmod_ksym_percpu __ksym;
extern void bpf_testmod_test_mod_kfunc(int i) __ksym;
extern void bpf_testmod_invalid_mod_kfunc(void) __ksym __weak;

int out_bpf_testmod_ksym = 0;
const volatile int x = 0;

SEC("classifier")
int handler(struct __sk_buff *skb)
{
	/* This should be preserved by clang, but DCE'd by verifier, and still
	 * allow loading the classifier prog
	 */
	if (x) {
		bpf_testmod_invalid_mod_kfunc();
		return -1;
	}
	bpf_testmod_test_mod_kfunc(42);
	out_bpf_testmod_ksym = *(int *)bpf_this_cpu_ptr(&bpf_testmod_ksym_percpu);
	return 0;
}

SEC("classifier")
int load_fail1(struct __sk_buff *skb)
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

SEC("classifier")
int load_fail2(struct __sk_buff *skb)
{
	KFUNC_VALID_DISTINCT_256;
	KFUNC_VALID_SAME_ONE;
	return 0;
}

SEC("classifier")
int load_256(struct __sk_buff *skb)
{
	/* this will fail if kfunc doesn't reuse its own btf fd index */
	KFUNC_VALID_SAME_256;
	KFUNC_VALID_SAME_ONE;
	return 0;
}

SEC("classifier")
int load_distinct256(struct __sk_buff *skb)
{
	/* kfuncs with distinct insn->imm, insn->off */
	KFUNC_VALID_DISTINCT_256;
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
