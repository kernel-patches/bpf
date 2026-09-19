// SPDX-License-Identifier: GPL-2.0-or-later

#include <kunit/test.h>

/* GSO */

#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <net/gso.h>

static const char hdr[] = "abcdefgh";
#define GSO_TEST_SIZE 1000

static void __init_skb(struct sk_buff *skb)
{
	skb_reset_mac_header(skb);
	memcpy(skb_mac_header(skb), hdr, sizeof(hdr));

	/* skb_segment expects skb->data at start of payload */
	skb_pull(skb, sizeof(hdr));
	skb_reset_network_header(skb);
	skb_reset_transport_header(skb);

	/* proto is arbitrary, as long as not ETH_P_TEB or vlan */
	skb->protocol = htons(ETH_P_ATALK);
	skb_shinfo(skb)->gso_size = GSO_TEST_SIZE;
}

enum gso_test_nr {
	GSO_TEST_LINEAR,
	GSO_TEST_NO_GSO,
	GSO_TEST_FRAGS,
	GSO_TEST_FRAGS_PURE,
	GSO_TEST_GSO_PARTIAL,
	GSO_TEST_FRAG_LIST,
	GSO_TEST_FRAG_LIST_PURE,
	GSO_TEST_FRAG_LIST_NON_UNIFORM,
	GSO_TEST_GSO_BY_FRAGS,
	GSO_TEST_BOUNDED,
	GSO_TEST_BOUNDED_MULTI,
	GSO_TEST_BOUNDED_ONE_MSS,
};

struct gso_test_case {
	enum gso_test_nr id;
	const char *name;

	/* input */
	unsigned int linear_len;
	unsigned int nr_frags;
	const unsigned int *frags;
	unsigned int nr_frag_skbs;
	const unsigned int *frag_skbs;
	unsigned int max_segs;

	/* output as expected */
	unsigned int nr_segs;
	const unsigned int *segs;
	bool segs_are_gso;
};

static struct gso_test_case cases[] = {
	{
		.id = GSO_TEST_NO_GSO,
		.name = "no_gso",
		.linear_len = GSO_TEST_SIZE,
		.nr_segs = 1,
		.segs = (const unsigned int[]) { GSO_TEST_SIZE },
	},
	{
		.id = GSO_TEST_LINEAR,
		.name = "linear",
		.linear_len = GSO_TEST_SIZE + GSO_TEST_SIZE + 1,
		.nr_segs = 3,
		.segs = (const unsigned int[]) { GSO_TEST_SIZE, GSO_TEST_SIZE, 1 },
	},
	{
		.id = GSO_TEST_FRAGS,
		.name = "frags",
		.linear_len = GSO_TEST_SIZE,
		.nr_frags = 2,
		.frags = (const unsigned int[]) { GSO_TEST_SIZE, 1 },
		.nr_segs = 3,
		.segs = (const unsigned int[]) { GSO_TEST_SIZE, GSO_TEST_SIZE, 1 },
	},
	{
		.id = GSO_TEST_FRAGS_PURE,
		.name = "frags_pure",
		.nr_frags = 3,
		.frags = (const unsigned int[]) { GSO_TEST_SIZE, GSO_TEST_SIZE, 2 },
		.nr_segs = 3,
		.segs = (const unsigned int[]) { GSO_TEST_SIZE, GSO_TEST_SIZE, 2 },
	},
	{
		.id = GSO_TEST_GSO_PARTIAL,
		.name = "gso_partial",
		.linear_len = GSO_TEST_SIZE,
		.nr_frags = 2,
		.frags = (const unsigned int[]) { GSO_TEST_SIZE, 3 },
		.nr_segs = 2,
		.segs = (const unsigned int[]) { 2 * GSO_TEST_SIZE, 3 },
	},
	{
		/* commit 89319d3801d1: frag_list on mss boundaries */
		.id = GSO_TEST_FRAG_LIST,
		.name = "frag_list",
		.linear_len = GSO_TEST_SIZE,
		.nr_frag_skbs = 2,
		.frag_skbs = (const unsigned int[]) { GSO_TEST_SIZE, GSO_TEST_SIZE },
		.nr_segs = 3,
		.segs = (const unsigned int[]) { GSO_TEST_SIZE, GSO_TEST_SIZE, GSO_TEST_SIZE },
	},
	{
		.id = GSO_TEST_FRAG_LIST_PURE,
		.name = "frag_list_pure",
		.nr_frag_skbs = 2,
		.frag_skbs = (const unsigned int[]) { GSO_TEST_SIZE, GSO_TEST_SIZE },
		.nr_segs = 2,
		.segs = (const unsigned int[]) { GSO_TEST_SIZE, GSO_TEST_SIZE },
	},
	{
		/* commit 43170c4e0ba7: GRO of frag_list trains */
		.id = GSO_TEST_FRAG_LIST_NON_UNIFORM,
		.name = "frag_list_non_uniform",
		.linear_len = GSO_TEST_SIZE,
		.nr_frag_skbs = 4,
		.frag_skbs = (const unsigned int[]) { GSO_TEST_SIZE, 1, GSO_TEST_SIZE, 2 },
		.nr_segs = 4,
		.segs = (const unsigned int[]) { GSO_TEST_SIZE, GSO_TEST_SIZE, GSO_TEST_SIZE, 3 },
	},
	{
		/* commit 3953c46c3ac7 ("sk_buff: allow segmenting based on frag sizes") and
		 * commit 90017accff61 ("sctp: Add GSO support")
		 *
		 * "there will be a cover skb with protocol headers and
		 *  children ones containing the actual segments"
		 */
		.id = GSO_TEST_GSO_BY_FRAGS,
		.name = "gso_by_frags",
		.nr_frag_skbs = 4,
		.frag_skbs = (const unsigned int[]) { 100, 200, 300, 400 },
		.nr_segs = 4,
		.segs = (const unsigned int[]) { 100, 200, 300, 400 },
	},
	{
		.id = GSO_TEST_BOUNDED,
		.name = "bounded",
		.linear_len = GSO_TEST_SIZE,
		.nr_frags = 3,
		.frags = (const unsigned int[]) {
			GSO_TEST_SIZE, GSO_TEST_SIZE, 3,
		},
		.max_segs = 2,
		.nr_segs = 2,
		.segs = (const unsigned int[]) {
			2 * GSO_TEST_SIZE, GSO_TEST_SIZE + 3,
		},
		.segs_are_gso = true,
	},
	{
		.id = GSO_TEST_BOUNDED_MULTI,
		.name = "bounded_multi",
		.linear_len = 2 * GSO_TEST_SIZE,
		.nr_frags = 4,
		.frags = (const unsigned int[]) {
			GSO_TEST_SIZE, GSO_TEST_SIZE, GSO_TEST_SIZE, 3,
		},
		.max_segs = 2,
		.nr_segs = 3,
		.segs = (const unsigned int[]) {
			2 * GSO_TEST_SIZE, 2 * GSO_TEST_SIZE, GSO_TEST_SIZE + 3,
		},
		.segs_are_gso = true,
	},
	{
		/*
		 * One MSS per skb is what the unbounded path produces, so a
		 * bound of a single segment must not change the output.
		 */
		.id = GSO_TEST_BOUNDED_ONE_MSS,
		.name = "bounded_one_mss",
		.linear_len = GSO_TEST_SIZE,
		.nr_frags = 3,
		.frags = (const unsigned int[]) {
			GSO_TEST_SIZE, GSO_TEST_SIZE, 3,
		},
		.max_segs = 1,
		.nr_segs = 4,
		.segs = (const unsigned int[]) {
			GSO_TEST_SIZE, GSO_TEST_SIZE, GSO_TEST_SIZE, 3,
		},
	},
};

static void gso_test_case_to_desc(struct gso_test_case *t, char *desc)
{
	sprintf(desc, "%s", t->name);
}

KUNIT_ARRAY_PARAM(gso_test, cases, gso_test_case_to_desc);

static void gso_test_func(struct kunit *test)
{
	const int shinfo_size = SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
	struct sk_buff *skb, *segs, *cur, *next, *last;
	const struct gso_test_case *tcase;
	netdev_features_t features;
	struct page *page;
	int i;

	tcase = test->param_value;

	page = alloc_page(GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, page);
	skb = build_skb(page_address(page), sizeof(hdr) + tcase->linear_len + shinfo_size);
	KUNIT_ASSERT_NOT_NULL(test, skb);
	__skb_put(skb, sizeof(hdr) + tcase->linear_len);

	__init_skb(skb);

	if (tcase->nr_frags) {
		unsigned int pg_off = 0;

		page = alloc_page(GFP_KERNEL);
		KUNIT_ASSERT_NOT_NULL(test, page);
		page_ref_add(page, tcase->nr_frags - 1);

		for (i = 0; i < tcase->nr_frags; i++) {
			skb_fill_page_desc(skb, i, page, pg_off, tcase->frags[i]);
			pg_off += tcase->frags[i];
		}

		KUNIT_ASSERT_LE(test, pg_off, PAGE_SIZE);

		skb->data_len = pg_off;
		skb->len += skb->data_len;
		skb->truesize += skb->data_len;
	}

	if (tcase->frag_skbs) {
		unsigned int total_size = 0, total_true_size = 0;
		struct sk_buff *frag_skb, *prev = NULL;

		for (i = 0; i < tcase->nr_frag_skbs; i++) {
			unsigned int frag_size;

			page = alloc_page(GFP_KERNEL);
			KUNIT_ASSERT_NOT_NULL(test, page);

			frag_size = tcase->frag_skbs[i];
			frag_skb = build_skb(page_address(page),
					     frag_size + shinfo_size);
			KUNIT_ASSERT_NOT_NULL(test, frag_skb);
			__skb_put(frag_skb, frag_size);

			if (prev)
				prev->next = frag_skb;
			else
				skb_shinfo(skb)->frag_list = frag_skb;
			prev = frag_skb;

			total_size += frag_size;
			total_true_size += frag_skb->truesize;
		}

		skb->len += total_size;
		skb->data_len += total_size;
		skb->truesize += total_true_size;

		if (tcase->id == GSO_TEST_GSO_BY_FRAGS)
			skb_shinfo(skb)->gso_size = GSO_BY_FRAGS;
	}

	features = NETIF_F_SG | NETIF_F_HW_CSUM;
	if (tcase->id == GSO_TEST_GSO_PARTIAL)
		features |= NETIF_F_GSO_PARTIAL;

	/* TODO: this should also work with SG,
	 * rather than hit BUG_ON(i >= nfrags)
	 */
	if (tcase->id == GSO_TEST_FRAG_LIST_NON_UNIFORM)
		features &= ~NETIF_F_SG;

	SKB_GSO_CB(skb)->max_segs = tcase->max_segs;
	segs = skb_segment(skb, features);
	if (IS_ERR(segs)) {
		KUNIT_FAIL(test, "segs error %pe", segs);
		goto free_gso_skb;
	} else if (!segs) {
		KUNIT_FAIL(test, "no segments");
		goto free_gso_skb;
	}

	last = segs->prev;
	for (cur = segs, i = 0; cur; cur = next, i++) {
		next = cur->next;

		KUNIT_ASSERT_EQ(test, cur->len, sizeof(hdr) + tcase->segs[i]);

		/* segs have skb->data pointing to the mac header */
		KUNIT_ASSERT_PTR_EQ(test, skb_mac_header(cur), cur->data);
		KUNIT_ASSERT_PTR_EQ(test, skb_network_header(cur), cur->data + sizeof(hdr));

		/* header was copied to all segs */
		KUNIT_ASSERT_EQ(test, memcmp(skb_mac_header(cur), hdr, sizeof(hdr)), 0);
		if (tcase->segs_are_gso) {
			KUNIT_EXPECT_TRUE(test, skb_is_gso(cur));
			KUNIT_EXPECT_EQ(test, skb_shinfo(cur)->gso_size,
					GSO_TEST_SIZE);
			KUNIT_EXPECT_LE(test, skb_shinfo(cur)->gso_segs,
					tcase->max_segs);
			KUNIT_EXPECT_FALSE(test, skb_shinfo(cur)->gso_type &
					 SKB_GSO_PARTIAL);
		}

		/* last seg can be found through segs->prev pointer */
		if (!next)
			KUNIT_ASSERT_PTR_EQ(test, cur, last);

		consume_skb(cur);
	}

	KUNIT_ASSERT_EQ(test, i, tcase->nr_segs);

free_gso_skb:
	consume_skb(skb);
}

#define GSO_TCP_HDR_LEN \
	(ETH_HLEN + sizeof(struct iphdr) + sizeof(struct tcphdr))

static struct sk_buff *gso_tcp_skb_new(unsigned int payload_len)
{
	struct sk_buff *skb;
	struct ethhdr *eth;
	struct tcphdr *th;
	struct iphdr *iph;

	skb = alloc_skb(GSO_TCP_HDR_LEN + payload_len, GFP_KERNEL);
	if (!skb)
		return NULL;
	skb_put_zero(skb, GSO_TCP_HDR_LEN + payload_len);

	skb_reset_mac_header(skb);
	eth = eth_hdr(skb);
	eth->h_proto = htons(ETH_P_IP);
	skb->protocol = eth->h_proto;

	skb_set_network_header(skb, ETH_HLEN);
	iph = ip_hdr(skb);
	iph->version = 4;
	iph->ihl = sizeof(*iph) / 4;
	iph->protocol = IPPROTO_TCP;
	iph->tot_len = htons(sizeof(*iph) + sizeof(*th) + payload_len);

	skb_set_transport_header(skb, ETH_HLEN + sizeof(*iph));
	th = tcp_hdr(skb);
	th->doff = sizeof(*th) / 4;

	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->csum_start = skb_transport_header(skb) - skb->head;
	skb->csum_offset = offsetof(struct tcphdr, check);
	skb_shinfo(skb)->gso_type = SKB_GSO_TCPV4;
	skb_shinfo(skb)->gso_size = GSO_TEST_SIZE;
	skb_shinfo(skb)->gso_segs = DIV_ROUND_UP(payload_len, GSO_TEST_SIZE);

	return skb;
}

static void gso_test_tcp_bounded_segment(struct kunit *test)
{
	netdev_features_t features = NETIF_F_SG | NETIF_F_HW_CSUM |
				     NETIF_F_TSO;
	const unsigned int payload_len = 3 * GSO_TEST_SIZE + 3;
	struct sk_buff *skb, *segs, *cur, *next;
	const unsigned int expected[] = {
		2 * GSO_TEST_SIZE, GSO_TEST_SIZE + 3,
	};
	const unsigned int max_segs = 2;
	int i = 0;

	skb = gso_tcp_skb_new(payload_len);
	KUNIT_ASSERT_NOT_NULL(test, skb);

	segs = __skb_gso_segment(skb, features, true, max_segs);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, segs);

	for (cur = segs; cur; cur = next, i++) {
		next = cur->next;

		KUNIT_ASSERT_LT(test, i, ARRAY_SIZE(expected));
		KUNIT_EXPECT_EQ(test, cur->len,
				GSO_TCP_HDR_LEN + expected[i]);
		KUNIT_EXPECT_TRUE(test, skb_is_gso(cur));
		KUNIT_EXPECT_EQ(test, skb_shinfo(cur)->gso_size,
				GSO_TEST_SIZE);
		KUNIT_EXPECT_LE(test, skb_shinfo(cur)->gso_segs, max_segs);

		consume_skb(cur);
	}

	KUNIT_EXPECT_EQ(test, i, ARRAY_SIZE(expected));
	consume_skb(skb);
}

#define GSO_TCP6_HDR_LEN \
	(ETH_HLEN + sizeof(struct ipv6hdr) + sizeof(struct tcphdr))

static struct sk_buff *gso_tcp6_skb_new(unsigned int payload_len)
{
	struct ipv6hdr *ip6h;
	struct sk_buff *skb;
	struct ethhdr *eth;
	struct tcphdr *th;

	skb = alloc_skb(GSO_TCP6_HDR_LEN + payload_len, GFP_KERNEL);
	if (!skb)
		return NULL;
	skb_put_zero(skb, GSO_TCP6_HDR_LEN + payload_len);

	skb_reset_mac_header(skb);
	eth = eth_hdr(skb);
	eth->h_proto = htons(ETH_P_IPV6);
	skb->protocol = eth->h_proto;

	skb_set_network_header(skb, ETH_HLEN);
	ip6h = ipv6_hdr(skb);
	ip6h->version = 6;
	ip6h->nexthdr = IPPROTO_TCP;
	ip6h->payload_len = htons(sizeof(*th) + payload_len);

	skb_set_transport_header(skb, ETH_HLEN + sizeof(*ip6h));
	th = tcp_hdr(skb);
	th->doff = sizeof(*th) / 4;

	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->csum_start = skb_transport_header(skb) - skb->head;
	skb->csum_offset = offsetof(struct tcphdr, check);
	skb_shinfo(skb)->gso_type = SKB_GSO_TCPV6;
	skb_shinfo(skb)->gso_size = GSO_TEST_SIZE;
	skb_shinfo(skb)->gso_segs = DIV_ROUND_UP(payload_len, GSO_TEST_SIZE);

	return skb;
}

/* The device GSO size limit is per L3 protocol, and it has to survive the
 * VLAN tag which validate_xmit_vlan() can push inside the skb, because that
 * tag replaces skb->protocol with the VLAN ethertype.
 */
static void gso_test_tcp_limit_l3_proto(struct kunit *test)
{
	static const struct net_device_ops dummy_netdev_ops = { };
	const unsigned int payload_len = 100 * 1024;
	netdev_features_t features;
	struct net_device *dev;
	struct sk_buff *skb;

	dev = alloc_etherdev(0);
	KUNIT_ASSERT_NOT_NULL(test, dev);
	dev->netdev_ops = &dummy_netdev_ops;
	dev->hw_features = NETIF_F_SG | NETIF_F_HW_CSUM | NETIF_F_TSO6;
	dev->features = dev->hw_features;
	dev->vlan_features = dev->hw_features;

	skb = gso_tcp6_skb_new(payload_len);
	KUNIT_ASSERT_NOT_NULL(test, skb);
	skb->dev = dev;

	/* The skb fits the IPv6 limit but not the IPv4 one. */
	dev->gso_max_size = GSO_MAX_SIZE;
	dev->gso_ipv4_max_size = GSO_LEGACY_MAX_SIZE;
	features = netif_skb_features(skb);
	KUNIT_EXPECT_TRUE(test, features & NETIF_F_GSO_MASK);

	/* ...and the other way around. */
	dev->gso_max_size = GSO_LEGACY_MAX_SIZE;
	dev->gso_ipv4_max_size = GSO_MAX_SIZE;
	features = netif_skb_features(skb);
	KUNIT_EXPECT_FALSE(test, features & NETIF_F_GSO_MASK);

	/* Pushing the tag inside must not change either answer. */
	skb = vlan_insert_tag_set_proto(skb, htons(ETH_P_8021Q), 0);
	KUNIT_ASSERT_NOT_NULL(test, skb);
	KUNIT_ASSERT_TRUE(test, skb->protocol == htons(ETH_P_8021Q));

	dev->gso_max_size = GSO_MAX_SIZE;
	dev->gso_ipv4_max_size = GSO_LEGACY_MAX_SIZE;
	features = netif_skb_features(skb);
	KUNIT_EXPECT_TRUE(test, features & NETIF_F_GSO_MASK);

	dev->gso_max_size = GSO_LEGACY_MAX_SIZE;
	dev->gso_ipv4_max_size = GSO_MAX_SIZE;
	features = netif_skb_features(skb);
	KUNIT_EXPECT_FALSE(test, features & NETIF_F_GSO_MASK);

	consume_skb(skb);
	free_netdev(dev);
}

/* IP tunnel flags */

#include <net/ip_tunnels.h>

struct ip_tunnel_flags_test {
	const char	*name;

	const u16	*src_bits;
	const u16	*exp_bits;
	u8		src_num;
	u8		exp_num;

	__be16		exp_val;
	bool		exp_comp;
};

#define IP_TUNNEL_FLAGS_TEST(n, src, comp, eval, exp) {	\
	.name		= (n),				\
	.src_bits	= (src),			\
	.src_num	= ARRAY_SIZE(src),		\
	.exp_comp	= (comp),			\
	.exp_val	= (eval),			\
	.exp_bits	= (exp),			\
	.exp_num	= ARRAY_SIZE(exp),		\
}

/* These are __be16-compatible and can be compared as is */
static const u16 ip_tunnel_flags_1[] = {
	IP_TUNNEL_KEY_BIT,
	IP_TUNNEL_STRICT_BIT,
	IP_TUNNEL_ERSPAN_OPT_BIT,
};

/* Due to the previous flags design limitation, setting either
 * ``IP_TUNNEL_CSUM_BIT`` (on Big Endian) or ``IP_TUNNEL_DONT_FRAGMENT_BIT``
 * (on Little) also sets VTI/ISATAP bit. In the bitmap implementation, they
 * correspond to ``BIT(16)``, which is bigger than ``U16_MAX``, but still is
 * backward-compatible.
 */
#ifdef __LITTLE_ENDIAN
#define IP_TUNNEL_CONFLICT_BIT	IP_TUNNEL_DONT_FRAGMENT_BIT
#else
#define IP_TUNNEL_CONFLICT_BIT	IP_TUNNEL_CSUM_BIT
#endif

static const u16 ip_tunnel_flags_2_src[] = {
	IP_TUNNEL_CONFLICT_BIT,
};

static const u16 ip_tunnel_flags_2_exp[] = {
	IP_TUNNEL_CONFLICT_BIT,
	IP_TUNNEL_SIT_ISATAP_BIT,
};

/* Bits 17 and higher are not compatible with __be16 flags */
static const u16 ip_tunnel_flags_3_src[] = {
	IP_TUNNEL_VXLAN_OPT_BIT,
	17,
	18,
	20,
};

static const u16 ip_tunnel_flags_3_exp[] = {
	IP_TUNNEL_VXLAN_OPT_BIT,
};

static const struct ip_tunnel_flags_test ip_tunnel_flags_test[] = {
	IP_TUNNEL_FLAGS_TEST("compat", ip_tunnel_flags_1, true,
			     cpu_to_be16(BIT(IP_TUNNEL_KEY_BIT) |
					 BIT(IP_TUNNEL_STRICT_BIT) |
					 BIT(IP_TUNNEL_ERSPAN_OPT_BIT)),
			     ip_tunnel_flags_1),
	IP_TUNNEL_FLAGS_TEST("conflict", ip_tunnel_flags_2_src, true,
			     VTI_ISVTI, ip_tunnel_flags_2_exp),
	IP_TUNNEL_FLAGS_TEST("new", ip_tunnel_flags_3_src, false,
			     cpu_to_be16(BIT(IP_TUNNEL_VXLAN_OPT_BIT)),
			     ip_tunnel_flags_3_exp),
};

static void
ip_tunnel_flags_test_case_to_desc(const struct ip_tunnel_flags_test *t,
				  char *desc)
{
	strscpy(desc, t->name, KUNIT_PARAM_DESC_SIZE);
}
KUNIT_ARRAY_PARAM(ip_tunnel_flags_test, ip_tunnel_flags_test,
		  ip_tunnel_flags_test_case_to_desc);

static void ip_tunnel_flags_test_run(struct kunit *test)
{
	const struct ip_tunnel_flags_test *t = test->param_value;
	IP_TUNNEL_DECLARE_FLAGS(src) = { };
	IP_TUNNEL_DECLARE_FLAGS(exp) = { };
	IP_TUNNEL_DECLARE_FLAGS(out);

	for (u32 j = 0; j < t->src_num; j++)
		__set_bit(t->src_bits[j], src);
	for (u32 j = 0; j < t->exp_num; j++)
		__set_bit(t->exp_bits[j], exp);

	KUNIT_ASSERT_EQ(test, t->exp_comp,
			ip_tunnel_flags_is_be16_compat(src));
	KUNIT_ASSERT_EQ(test, (__force u16)t->exp_val,
			(__force u16)ip_tunnel_flags_to_be16(src));

	ip_tunnel_flags_from_be16(out, t->exp_val);
	KUNIT_ASSERT_TRUE(test, __ipt_flag_op(bitmap_equal, exp, out));
}

static struct kunit_case net_test_cases[] = {
	KUNIT_CASE_PARAM(gso_test_func, gso_test_gen_params),
	KUNIT_CASE(gso_test_tcp_bounded_segment),
	KUNIT_CASE(gso_test_tcp_limit_l3_proto),
	KUNIT_CASE_PARAM(ip_tunnel_flags_test_run,
			 ip_tunnel_flags_test_gen_params),
	{ },
};

static struct kunit_suite net_test_suite = {
	.name		= "net_core",
	.test_cases	= net_test_cases,
};
kunit_test_suite(net_test_suite);

MODULE_DESCRIPTION("KUnit tests for networking core");
MODULE_LICENSE("GPL");
