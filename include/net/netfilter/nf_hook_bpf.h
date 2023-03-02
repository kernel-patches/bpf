/* SPDX-License-Identifier: GPL-2.0 */

struct bpf_nf_ctx {
	const struct nf_hook_state *state;
	struct sk_buff *skb;
};

int bpf_nf_link_attach(const union bpf_attr *attr, struct bpf_prog *prog);
