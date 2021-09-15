// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

extern void bpf_testmod_test_mod_kfunc(int i) __ksym;
extern void bpf_testmod_invalid_mod_kfunc(void) __ksym __weak;

const volatile int x = 0;

SEC("raw_tp/sys_enter")
int handler_pass(const void *ctx)
{
	/* This should be preserved by clang, but DCE'd by verifier, and still
	 * allow loading the raw_tp prog
	 */
	if (x)
		bpf_testmod_invalid_mod_kfunc();
	bpf_testmod_test_mod_kfunc(42);
	return 0;
}

SEC("raw_tp/sys_enter")
int handler_fail(const void *ctx)
{
	/* This call should be preserved by clang, but fail verification.
	 */
	if (!x)
		bpf_testmod_invalid_mod_kfunc();
	bpf_testmod_test_mod_kfunc(42);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
