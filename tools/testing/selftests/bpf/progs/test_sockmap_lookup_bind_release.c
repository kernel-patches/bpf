// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, int);
} sockmap SEC(".maps");

SEC("cgroup/connect4")
int connect(struct bpf_sock_addr *ctx)
{
	struct bpf_sock *sk;
	int ret = SK_DROP;

	sk = bpf_map_lookup_elem(&sockmap, &(int){0});
	if (sk) {
		if (sk == ctx->sk) {
			struct sockaddr_in sa = {
				.sin_family = ctx->user_family,
				.sin_port = ctx->user_port,
				.sin_addr.s_addr = ctx->user_ip4
			};

			ret = !bpf_bind(ctx, (struct sockaddr *)&sa, sizeof(sa));
		}

		bpf_sk_release(sk);
	}

	return ret;
}

char _license[] SEC("license") = "GPL";
