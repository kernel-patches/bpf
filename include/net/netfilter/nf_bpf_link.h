/* SPDX-License-Identifier: GPL-2.0 */

#if __has_attribute(preserve_static_offset) && defined(__bpf__)
#define __bpf_ctx __attribute__((preserve_static_offset))
#elif __has_attribute(btf_decl_tag) && !defined(__cplusplus)
#define __bpf_ctx __attribute__((btf_decl_tag(("preserve_static_offset"))))
#else
#define __bpf_ctx
#endif

struct bpf_nf_ctx {
	const struct nf_hook_state *state;
	struct sk_buff *skb;
} __bpf_ctx;

#if IS_ENABLED(CONFIG_NETFILTER_BPF_LINK)
int bpf_nf_link_attach(const union bpf_attr *attr, struct bpf_prog *prog);
#else
static inline int bpf_nf_link_attach(const union bpf_attr *attr, struct bpf_prog *prog)
{
	return -EOPNOTSUPP;
}
#endif

#undef __bpf_ctx
