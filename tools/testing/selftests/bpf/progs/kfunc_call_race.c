// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

extern void bpf_mod_kfunc_race_test(void) __ksym;

SEC("tc")
int kfunc_call_fail(struct __sk_buff *ctx)
{
	bpf_mod_kfunc_race_test();
	return 0;
}

char _license[] SEC("license") = "GPL";
