// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <stdint.h>

__u64 test_result_frags_count = UINT64_MAX;
__u64 test_result_frags_len = UINT64_MAX;
__u64 test_result_xdp_len = UINT64_MAX;

SEC("xdp_check_mb_len")
int _xdp_check_mb_len(struct xdp_md *xdp)
{
	void *data_end = (void *)(long)xdp->data_end;
	void *data = (void *)(long)xdp->data;

	test_result_xdp_len = (__u64)(data_end - data);
	test_result_frags_len = bpf_xdp_get_frags_total_size(xdp);
	test_result_frags_count = bpf_xdp_get_frags_count(xdp);
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
