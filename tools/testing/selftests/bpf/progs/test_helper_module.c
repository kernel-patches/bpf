// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

extern int bpf_helper_print_add(int *a, int *b) __ksym;

SEC("tc")
int load(struct __sk_buff *skb)
{
	int a, b;

	a = 3;
	b = 4;
	return bpf_helper_print_add(&a, &b);
}

char LICENSE[] SEC("license") = "GPL";
