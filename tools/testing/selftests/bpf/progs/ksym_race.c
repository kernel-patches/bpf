// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

extern int bpf_mod_kfunc_race_ksym __ksym;

SEC("tc")
int ksym_fail(struct __sk_buff *ctx)
{
	return *(int *)bpf_this_cpu_ptr(&bpf_mod_kfunc_race_ksym);
}

char _license[] SEC("license") = "GPL";
