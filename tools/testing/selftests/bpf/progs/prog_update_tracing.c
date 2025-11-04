// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

__u64 sequence = 0;

__u64 fentry1_seq = 0;
__u64 fentry1_cookie = 0;
SEC("fentry/bpf_modify_return_test")
int BPF_PROG(fentry1, int a, __u64 b)
{
	fentry1_seq = ++sequence;
	fentry1_cookie = bpf_get_attach_cookie(ctx);
	return 0;
}

__u64 fentry2_seq = 0;
__u64 fentry2_cookie = 0;
SEC("fentry/bpf_modify_return_test")
int BPF_PROG(fentry2, int a, __u64 b)
{
	fentry2_seq = ++sequence;
	fentry2_cookie = bpf_get_attach_cookie(ctx);
	return 0;
}

__u64 fmod_ret1_seq = 0;
__u64 fmod_ret1_cookie = 0;
SEC("fmod_ret/bpf_modify_return_test")
int BPF_PROG(fmod_ret1, int a, int *b, int ret)
{
	fmod_ret1_seq = ++sequence;
	fmod_ret1_cookie = bpf_get_attach_cookie(ctx);
	return ret;
}

__u64 fmod_ret2_seq = 0;
__u64 fmod_ret2_cookie = 0;
SEC("fmod_ret/bpf_modify_return_test")
int BPF_PROG(fmod_ret2, int a, int *b, int ret)
{
	fmod_ret2_seq = ++sequence;
	fmod_ret2_cookie = bpf_get_attach_cookie(ctx);
	return ret;
}

__u64 fexit1_seq = 0;
__u64 fexit1_cookie = 0;
SEC("fexit/bpf_modify_return_test")
int BPF_PROG(fexit1, int a, __u64 b, int ret)
{
	fexit1_seq = ++sequence;
	fexit1_cookie = bpf_get_attach_cookie(ctx);
	return 0;
}

__u64 fexit2_seq = 0;
__u64 fexit2_cookie = 0;
SEC("fexit/bpf_modify_return_test")
int BPF_PROG(fexit2, int a, __u64 b, int ret)
{
	fexit2_seq = ++sequence;
	fexit2_cookie = bpf_get_attach_cookie(ctx);
	return 0;
}

__u64 sequence_bpf = 0;

__u64 fentry1_bpf_seq = 0;
__u64 fentry1_bpf_cookie = 0;
SEC("fentry/test_pkt_access")
int fentry1_bpf(struct __sk_buff *skb)
{
	fentry1_bpf_seq = ++sequence_bpf;
	fentry1_bpf_cookie = bpf_get_attach_cookie(skb);
	return 0;
}

__u64 fentry2_bpf_seq = 0;
__u64 fentry2_bpf_cookie = 0;
SEC("fentry/test_pkt_access")
int fentry2_bpf(struct __sk_buff *skb)
{
	fentry2_bpf_seq = ++sequence_bpf;
	fentry2_bpf_cookie = bpf_get_attach_cookie(skb);
	return 0;
}

__u64 freplace1_bpf_seq = 0;
SEC("freplace/test_pkt_access_subprog3")
int freplace1_bpf(int val, struct __sk_buff *skb)
{
	freplace1_bpf_seq = ++sequence_bpf;
	return 0;
}

__u64 freplace2_bpf_seq = 0;
SEC("freplace/test_pkt_access_subprog3")
int freplace2_bpf(int val, struct __sk_buff *skb)
{
	freplace2_bpf_seq = ++sequence_bpf;
	return 0;
}

SEC("freplace/get_skb_ifindex")
int freplace3_bpf(int val, struct __sk_buff *skb, int var)
{
	return 0;
}

__u64 fexit1_bpf_seq = 0;
__u64 fexit1_bpf_cookie = 0;
SEC("fexit/test_pkt_access")
int fexit1_bpf(struct __sk_buff *skb, int ret)
{
	fexit1_bpf_seq = ++sequence_bpf;
	fexit1_bpf_cookie = bpf_get_attach_cookie(skb);
	return 0;
}

__u64 fexit2_bpf_seq = 0;
__u64 fexit2_bpf_cookie = 0;
SEC("fexit/test_pkt_access")
int fexit2_bpf(struct __sk_buff *skb, int ret)
{
	fexit2_bpf_seq = ++sequence_bpf;
	fexit2_bpf_cookie = bpf_get_attach_cookie(skb);
	return 0;
}

char _license[] SEC("license") = "GPL";
