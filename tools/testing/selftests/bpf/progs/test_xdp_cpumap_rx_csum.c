// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include "bpf_tracing_net.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

extern int bpf_xdp_assert_rx_csum(struct xdp_md *ctx) __ksym;

struct {
	__uint(type, BPF_MAP_TYPE_CPUMAP);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct bpf_cpumap_val));
	__uint(max_entries, 1);
} cpu_map SEC(".maps");

/* Set from userspace before injecting each packet. */
bool assert_csum = false;

/* Filled in by the fexit program when the cpumap skb is built. */
bool seen = false;
int observed_ip_summed = -1;

SEC("xdp")
int xdp_redir(struct xdp_md *ctx)
{
	/* Assert the L4 checksum so the skb built on the cpumap redirect
	 * path is marked CHECKSUM_UNNECESSARY instead of validated in software.
	 */
	if (assert_csum)
		bpf_xdp_assert_rx_csum(ctx);

	return bpf_redirect_map(&cpu_map, 0, 0);
}

/* Observe ip_summed exactly as __xdp_build_skb_from_frame() leaves it, before
 * GRO in the cpumap kthread can normalize it. tc-ingress would be too late:
 * GRO software-validates a CHECKSUM_NONE skb and marks it UNNECESSARY anyway.
 */
SEC("fexit/__xdp_build_skb_from_frame")
int BPF_PROG(on_build, struct xdp_frame *xdpf, struct sk_buff *skb,
	     struct net_device *dev, struct sk_buff *ret)
{
	if (ret && ret->protocol == bpf_htons(ETH_P_IPV6)) {
		observed_ip_summed = ret->ip_summed;
		seen = true;
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
