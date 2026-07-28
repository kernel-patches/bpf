// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

#define STR_BENCH_CAP 2048

static const char span_reject[] __aligned(8) = ":";
static const char substring_needle[] __aligned(8) =
	"Host: benchmark.example.com";

/* Populated by userspace once per scenario, outside the timed program run. */
struct {
	struct {
		__u64 words[(STR_BENCH_CAP + sizeof(__u64)) / sizeof(__u64)];
	} lhs;
	struct {
		__u64 words[(STR_BENCH_CAP + sizeof(__u64)) / sizeof(__u64)];
	} rhs;
} buffers SEC(".data");

__u32 payload_length SEC(".data");

SEC("tc")
int scan_kfunc(struct __sk_buff *skb)
{
	return bpf_strnchr((const char *)buffers.lhs.words, payload_length, 'H');
}

SEC("tc")
int compare_kfunc(struct __sk_buff *skb)
{
	return bpf_strcmp((const char *)buffers.lhs.words, (const char *)buffers.rhs.words);
}

SEC("tc")
int span_kfunc(struct __sk_buff *skb)
{
	return bpf_strcspn((const char *)buffers.lhs.words, span_reject);
}

SEC("tc")
int substring_kfunc(struct __sk_buff *skb)
{
	return bpf_strnstr((const char *)buffers.lhs.words, substring_needle, payload_length);
}

char _license[] SEC("license") = "GPL";
