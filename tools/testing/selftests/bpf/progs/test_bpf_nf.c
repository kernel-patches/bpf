// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define EAFNOSUPPORT 97
#define EPROTO 71
#define ENONET 64
#define EINVAL 22
#define ENOENT 2

extern unsigned long CONFIG_HZ __kconfig;

int test_einval_bpf_tuple = 0;
int test_einval_reserved = 0;
int test_einval_netns_id = 0;
int test_einval_len_opts = 0;
int test_eproto_l4proto = 0;
int test_enonet_netns_id = 0;
int test_enoent_lookup = 0;
int test_eafnosupport = 0;
int test_succ_lookup = 0;
u32 test_delta_timeout = 0;

struct nf_conn;

struct bpf_ct_opts___local {
	s32 netns_id;
	s32 error;
	u8 l4proto;
	u8 reserved[3];
} __attribute__((preserve_access_index));

struct nf_conn *bpf_xdp_ct_lookup(struct xdp_md *, struct bpf_sock_tuple *, u32,
				  struct bpf_ct_opts___local *, u32) __ksym;
struct nf_conn *bpf_skb_ct_lookup(struct __sk_buff *, struct bpf_sock_tuple *, u32,
				  struct bpf_ct_opts___local *, u32) __ksym;
void bpf_ct_release(struct nf_conn *) __ksym;
void bpf_ct_refresh_timeout(struct nf_conn *, u32) __ksym;

static __always_inline void
nf_ct_test(struct nf_conn *(*func)(void *, struct bpf_sock_tuple *, u32,
				   struct bpf_ct_opts___local *, u32),
	   void *ctx)
{
	struct bpf_ct_opts___local opts_def = { .l4proto = IPPROTO_TCP, .netns_id = -1 };
	struct bpf_sock_tuple bpf_tuple;
	struct nf_conn *ct;

	__builtin_memset(&bpf_tuple, 0, sizeof(bpf_tuple.ipv4));

	ct = func(ctx, NULL, 0, &opts_def, sizeof(opts_def));
	if (ct)
		bpf_ct_release(ct);
	else
		test_einval_bpf_tuple = opts_def.error;

	opts_def.reserved[0] = 1;
	ct = func(ctx, &bpf_tuple, sizeof(bpf_tuple.ipv4), &opts_def, sizeof(opts_def));
	opts_def.reserved[0] = 0;
	opts_def.l4proto = IPPROTO_TCP;
	if (ct)
		bpf_ct_release(ct);
	else
		test_einval_reserved = opts_def.error;

	opts_def.netns_id = -2;
	ct = func(ctx, &bpf_tuple, sizeof(bpf_tuple.ipv4), &opts_def, sizeof(opts_def));
	opts_def.netns_id = -1;
	if (ct)
		bpf_ct_release(ct);
	else
		test_einval_netns_id = opts_def.error;

	ct = func(ctx, &bpf_tuple, sizeof(bpf_tuple.ipv4), &opts_def, sizeof(opts_def) - 1);
	if (ct)
		bpf_ct_release(ct);
	else
		test_einval_len_opts = opts_def.error;

	opts_def.l4proto = IPPROTO_ICMP;
	ct = func(ctx, &bpf_tuple, sizeof(bpf_tuple.ipv4), &opts_def, sizeof(opts_def));
	opts_def.l4proto = IPPROTO_TCP;
	if (ct)
		bpf_ct_release(ct);
	else
		test_eproto_l4proto = opts_def.error;

	opts_def.netns_id = 0xf00f;
	ct = func(ctx, &bpf_tuple, sizeof(bpf_tuple.ipv4), &opts_def, sizeof(opts_def));
	opts_def.netns_id = -1;
	if (ct)
		bpf_ct_release(ct);
	else
		test_enonet_netns_id = opts_def.error;

	ct = func(ctx, &bpf_tuple, sizeof(bpf_tuple.ipv4), &opts_def, sizeof(opts_def));
	if (ct)
		bpf_ct_release(ct);
	else
		test_enoent_lookup = opts_def.error;

	ct = func(ctx, &bpf_tuple, sizeof(bpf_tuple.ipv4) - 1, &opts_def, sizeof(opts_def));
	if (ct)
		bpf_ct_release(ct);
	else
		test_eafnosupport = opts_def.error;

	bpf_tuple.ipv4.saddr = 0x01010101; /* src IP 1.1.1.1 */
	bpf_tuple.ipv4.daddr = 0x02020202; /* dst IP 2.2.2.2 */
	bpf_tuple.ipv4.sport = bpf_htons(12345); /* src port */
	bpf_tuple.ipv4.dport = bpf_htons(1000);  /* dst port */
	ct = func(ctx, &bpf_tuple, sizeof(bpf_tuple.ipv4), &opts_def,
		  sizeof(opts_def));
	if (ct) {
		/* update ct entry timeout */
		bpf_ct_refresh_timeout(ct, 10000);
		test_delta_timeout = ct->timeout - bpf_jiffies64();
		test_delta_timeout /= CONFIG_HZ;
		bpf_ct_release(ct);
	} else {
		test_succ_lookup = opts_def.error;
	}
}

SEC("xdp")
int nf_xdp_ct_test(struct xdp_md *ctx)
{
	nf_ct_test((void *)bpf_xdp_ct_lookup, ctx);
	return 0;
}

SEC("tc")
int nf_skb_ct_test(struct __sk_buff *ctx)
{
	nf_ct_test((void *)bpf_skb_ct_lookup, ctx);
	return 0;
}

char _license[] SEC("license") = "GPL";
