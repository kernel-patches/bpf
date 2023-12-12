// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* A dummy program that references __sk_buff type in it's BTF,
 * used by test_bpftool.py.
 */
SEC("tc")
int sk_buff_user(struct __sk_buff *skb)
{
	return 0;
}

char _license[] SEC("license") = "GPL";
