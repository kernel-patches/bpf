// SPDX-License-Identifier: GPL-2.0-or-later
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Initialization/cleanup for QUIC protocol support.
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#include <net/inet_common.h>
#include <net/udp_tunnel.h>
#include <linux/icmp.h>

#include "common.h"
#include "family.h"

static bool quic_v4_is_any_addr(union quic_addr *addr)
{
	return addr->v4.sin_addr.s_addr == htonl(INADDR_ANY);
}

static bool quic_v6_is_any_addr(union quic_addr *addr)
{
	return ipv6_addr_any(&addr->v6.sin6_addr);
}

static void quic_v4_udp_conf_init(struct sock *sk, struct udp_port_cfg *conf,
				  union quic_addr *a)
{
	conf->family = AF_INET;
	conf->local_ip.s_addr = a->v4.sin_addr.s_addr;
	conf->local_udp_port = a->v4.sin_port;
	conf->bind_ifindex = sk->sk_bound_dev_if;
}

static void quic_v6_udp_conf_init(struct sock *sk, struct udp_port_cfg *conf,
				  union quic_addr *a)
{
	conf->family = AF_INET6;
	conf->local_ip6 = a->v6.sin6_addr;
	conf->local_udp_port = a->v6.sin6_port;
	conf->use_udp6_rx_checksums = true;
	conf->use_udp6_tx_checksums = true;
	conf->ipv6_v6only = ipv6_only_sock(sk);
	conf->bind_ifindex = quic_get_dev_if(sk, a);
}

static int quic_v4_flow_route(struct sock *sk, union quic_addr *da,
			      union quic_addr *sa, struct flowi *fl)
{
	struct flowi4 *fl4;
	struct rtable *rt;

	if (__sk_dst_check(sk, 0))
		return 1;

	memset(fl, 0x00, sizeof(*fl));
	fl4 = &fl->u.ip4;
	fl4->saddr = sa->v4.sin_addr.s_addr;
	fl4->fl4_sport = sa->v4.sin_port;
	fl4->daddr = da->v4.sin_addr.s_addr;
	fl4->fl4_dport = da->v4.sin_port;
	fl4->flowi4_proto = IPPROTO_UDP;
	fl4->flowi4_oif = quic_get_dev_if(sk, da);

	fl4->flowi4_scope = ip_sock_rt_scope(sk);
	fl4->flowi4_dscp = inet_sk_dscp(inet_sk(sk));

	fl4->flowi4_uid = sk_uid(sk);
	fl4->flowi4_mark = sk->sk_mark;

	rt = ip_route_output_flow(sock_net(sk), fl4, sk);
	if (IS_ERR(rt))
		return PTR_ERR(rt);

	if (quic_v4_is_any_addr(sa)) {
		sa->v4.sin_family = AF_INET;
		sa->v4.sin_addr.s_addr = fl4->saddr;
	}
	sk_setup_caps(sk, &rt->dst);
	return 0;
}

static int quic_v6_flow_route(struct sock *sk, union quic_addr *da,
			      union quic_addr *sa, struct flowi *fl)
{
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct in6_addr *final_p, final;
	struct ip6_flowlabel *flowlabel;
	struct dst_entry *dst;
	struct flowi6 *fl6;

	if (__sk_dst_check(sk, np->dst_cookie))
		return 1;

	memset(fl, 0x00, sizeof(*fl));
	fl6 = &fl->u.ip6;
	fl6->saddr = sa->v6.sin6_addr;
	fl6->fl6_sport = sa->v6.sin6_port;
	fl6->daddr = da->v6.sin6_addr;
	fl6->fl6_dport = da->v6.sin6_port;
	fl6->flowi6_proto = IPPROTO_UDP;
	fl6->flowi6_oif = quic_get_dev_if(sk, da);

	if (inet6_test_bit(SNDFLOW, sk)) {
		fl6->flowlabel = (da->v6.sin6_flowinfo & IPV6_FLOWINFO_MASK);
		if (fl6->flowlabel & IPV6_FLOWLABEL_MASK) {
			flowlabel = fl6_sock_lookup(sk, fl6->flowlabel);
			if (IS_ERR(flowlabel))
				return -EINVAL;
			fl6_sock_release(flowlabel);
		}
	}
	fl6->flowlabel = ip6_make_flowinfo(np->tclass, fl6->flowlabel);

	fl6->flowi6_uid = sk_uid(sk);
	fl6->flowi6_mark = sk->sk_mark;

	rcu_read_lock();
	final_p = fl6_update_dst(fl6, rcu_dereference(np->opt), &final);
	rcu_read_unlock();

	dst = ip6_dst_lookup_flow(sock_net(sk), sk, fl6, final_p);
	if (IS_ERR(dst))
		return PTR_ERR(dst);

	if (quic_v6_is_any_addr(sa)) {
		sa->v6.sin6_family = AF_INET6;
		sa->v6.sin6_addr = fl6->saddr;
		if ((ipv6_addr_type(&fl6->saddr) & IPV6_ADDR_LINKLOCAL))
			sa->v6.sin6_scope_id = fl6->flowi6_oif;
	}
	ip6_dst_store(sk, dst, false, false);
	return 0;
}

static void quic_v4_lower_xmit(struct sock *sk, struct sk_buff *skb,
			       struct flowi *fl)
{
	struct quic_skb_cb *cb = QUIC_SKB_CB(skb);
	struct flowi4 *fl4 = &fl->u.ip4;
	u8 tos = inet_sk(sk)->tos, ttl;
	struct dst_entry *dst;
	__be16 df = 0;

	pr_debug("%s: skb: %p, len: %d, num: %lld, %pI4:%d -> %pI4:%d\n",
		 __func__, skb, skb->len, cb->number, &fl4->saddr,
		 ntohs(fl4->fl4_sport), &fl4->daddr, ntohs(fl4->fl4_dport));

	dst = sk_dst_get(sk);
	if (!dst) {
		kfree_skb(skb);
		return;
	}
	if (ip_dont_fragment(sk, dst) && !skb->ignore_df)
		df = htons(IP_DF);

	if (cb->ecn)
		tos = (tos & ~INET_ECN_MASK) | cb->ecn;
	ttl = (u8)ip4_dst_hoplimit(dst);
	udp_tunnel_xmit_skb((struct rtable *)dst, sk, skb, fl4->saddr,
			    fl4->daddr, tos, ttl, df, fl4->fl4_sport,
			    fl4->fl4_dport, false, false, 0);
}

static void quic_v6_lower_xmit(struct sock *sk, struct sk_buff *skb,
			       struct flowi *fl)
{
	struct quic_skb_cb *cb = QUIC_SKB_CB(skb);
	u8 tc = inet6_sk(sk)->tclass, ttl;
	struct flowi6 *fl6 = &fl->u.ip6;
	struct dst_entry *dst;
	__be32 label;

	pr_debug("%s: skb: %p, len: %d, num: %lld, %pI6c:%d -> %pI6c:%d\n",
		 __func__, skb, skb->len, cb->number, &fl6->saddr,
		 ntohs(fl6->fl6_sport), &fl6->daddr, ntohs(fl6->fl6_dport));

	dst = sk_dst_get(sk);
	if (!dst) {
		kfree_skb(skb);
		return;
	}

	if (cb->ecn)
		tc = (tc & ~INET_ECN_MASK) | cb->ecn;
	ttl = (u8)ip6_dst_hoplimit(dst);
	label = ip6_make_flowlabel(sock_net(sk), skb, fl6->flowlabel, true,
				   fl6);
	udp_tunnel6_xmit_skb(dst, sk, skb, NULL, &fl6->saddr, &fl6->daddr, tc,
			     ttl, label, fl6->fl6_sport, fl6->fl6_dport, false,
			     0);
}

static void quic_v4_get_msg_addrs(struct sk_buff *skb, union quic_addr *da,
				  union quic_addr *sa)
{
	struct udphdr *uh = udp_hdr(skb);

	sa->v4.sin_family = AF_INET;
	sa->v4.sin_port = uh->source;
	sa->v4.sin_addr.s_addr = ip_hdr(skb)->saddr;

	da->v4.sin_family = AF_INET;
	da->v4.sin_port = uh->dest;
	da->v4.sin_addr.s_addr = ip_hdr(skb)->daddr;
}

static void quic_v6_get_msg_addrs(struct sk_buff *skb, union quic_addr *da,
				  union quic_addr *sa)
{
	struct udphdr *uh = udp_hdr(skb);

	sa->v6.sin6_family = AF_INET6;
	sa->v6.sin6_port = uh->source;
	sa->v6.sin6_addr = ipv6_hdr(skb)->saddr;
	sa->v6.sin6_scope_id = skb->skb_iif;

	da->v6.sin6_family = AF_INET6;
	da->v6.sin6_port = uh->dest;
	da->v6.sin6_addr = ipv6_hdr(skb)->daddr;
	da->v6.sin6_scope_id = skb->skb_iif;
}

static int quic_v4_get_mtu_info(struct sk_buff *skb, u32 *info)
{
	struct icmphdr *hdr;

	hdr = (struct icmphdr *)(skb_network_header(skb) -
				 sizeof(struct icmphdr));
	if (hdr->type == ICMP_DEST_UNREACH && hdr->code == ICMP_FRAG_NEEDED) {
		*info = ntohs(hdr->un.frag.mtu);
		return 0;
	}

	/* Defer other types' processing to UDP error handler. */
	return -EINVAL;
}

static int quic_v6_get_mtu_info(struct sk_buff *skb, u32 *info)
{
	struct icmp6hdr *hdr;

	hdr = (struct icmp6hdr *)(skb_network_header(skb) -
				  sizeof(struct icmp6hdr));
	if (hdr->icmp6_type == ICMPV6_PKT_TOOBIG) {
		*info = ntohl(hdr->icmp6_mtu);
		return 0;
	}

	/* Defer other types' processing to UDP error handler. */
	return -EINVAL;
}

static bool quic_v4_cmp_sk_addr(struct sock *sk, union quic_addr *a,
				union quic_addr *addr)
{
	if (a->v4.sin_port != addr->v4.sin_port)
		return false;
	if (a->v4.sin_family != addr->v4.sin_family)
		return false;
	/* Match only if socket is also ANY-bound. */
	if (addr->v4.sin_addr.s_addr == htonl(INADDR_ANY))
		return a->v4.sin_addr.s_addr == htonl(INADDR_ANY);
	if (a->v4.sin_addr.s_addr == htonl(INADDR_ANY))
		return true;
	return a->v4.sin_addr.s_addr == addr->v4.sin_addr.s_addr;
}

static bool quic_v6_cmp_sk_addr(struct sock *sk, union quic_addr *a,
				union quic_addr *addr)
{
	if (a->sa.sa_family == AF_INET && addr->sa.sa_family == AF_INET)
		return quic_v4_cmp_sk_addr(sk, a, addr);

	if (a->v4.sin_port != addr->v4.sin_port)
		return false;

	if (a->sa.sa_family != addr->sa.sa_family) {
		if (ipv6_only_sock(sk) || a->sa.sa_family == AF_INET)
			return false;
		return quic_is_any_addr(a);
	}

	/* Match only if socket is also ANY-bound. */
	if (ipv6_addr_any(&addr->v6.sin6_addr))
		return ipv6_addr_any(&a->v6.sin6_addr);
	if (ipv6_addr_any(&a->v6.sin6_addr))
		return true;
	if (!ipv6_addr_equal(&a->v6.sin6_addr, &addr->v6.sin6_addr))
		return false;
	if ((ipv6_addr_type(&a->v6.sin6_addr) & IPV6_ADDR_LINKLOCAL) &&
	    a->v6.sin6_scope_id && addr->v6.sin6_scope_id &&
	    a->v6.sin6_scope_id != addr->v6.sin6_scope_id)
		return false;
	return true;
}

static int quic_v4_get_sk_addr(struct socket *sock, struct sockaddr *uaddr,
			       int peer)
{
	return inet_getname(sock, uaddr, peer);
}

static int quic_v6_get_sk_addr(struct socket *sock, struct sockaddr *uaddr,
			       int peer)
{
	union quic_addr *a = quic_addr(uaddr);
	int ret;

	ret = inet6_getname(sock, uaddr, peer);
	if (ret < 0)
		return ret;

	if (a->sa.sa_family == AF_INET6 &&
	    ipv6_addr_v4mapped(&a->v6.sin6_addr)) {
		a->v4.sin_family = AF_INET;
		a->v4.sin_port = a->v6.sin6_port;
		a->v4.sin_addr.s_addr = a->v6.sin6_addr.s6_addr32[3];
	}

	if (a->sa.sa_family == AF_INET) {
		memset(a->v4.sin_zero, 0, sizeof(a->v4.sin_zero));
		return sizeof(struct sockaddr_in);
	}
	return sizeof(struct sockaddr_in6);
}

#define quic_af_ipv4(a)		((a)->sa.sa_family == AF_INET)

u32 quic_encap_len(union quic_addr *a)
{
	return (quic_af_ipv4(a) ? sizeof(struct iphdr) :
				  sizeof(struct ipv6hdr)) +
	       sizeof(struct udphdr);
}

bool quic_is_any_addr(union quic_addr *a)
{
	return quic_af_ipv4(a) ? quic_v4_is_any_addr(a) :
				 quic_v6_is_any_addr(a);
}

void quic_udp_conf_init(struct sock *sk, struct udp_port_cfg *conf,
			union quic_addr *a)
{
	quic_af_ipv4(a) ? quic_v4_udp_conf_init(sk, conf, a) :
			  quic_v6_udp_conf_init(sk, conf, a);
}

int quic_flow_route(struct sock *sk, union quic_addr *da, union quic_addr *sa,
		    struct flowi *fl)
{
	if (sa->sa.sa_family && da->sa.sa_family != sa->sa.sa_family)
		return -EINVAL;

	return quic_af_ipv4(da) ? quic_v4_flow_route(sk, da, sa, fl) :
				  quic_v6_flow_route(sk, da, sa, fl);
}

void quic_lower_xmit(struct sock *sk, struct sk_buff *skb, union quic_addr *da,
		     struct flowi *fl)
{
	local_bh_disable();
	quic_af_ipv4(da) ? quic_v4_lower_xmit(sk, skb, fl) :
			   quic_v6_lower_xmit(sk, skb, fl);
	local_bh_enable();
}

#define quic_skb_ipv4(skb)	(ip_hdr(skb)->version == 4)

void quic_get_msg_addrs(struct sk_buff *skb, union quic_addr *da,
			union quic_addr *sa)
{
	memset(sa, 0, sizeof(*sa));
	memset(da, 0, sizeof(*da));
	quic_skb_ipv4(skb) ? quic_v4_get_msg_addrs(skb, da, sa) :
			     quic_v6_get_msg_addrs(skb, da, sa);
}

int quic_get_mtu_info(struct sk_buff *skb, u32 *info)
{
	return quic_skb_ipv4(skb) ? quic_v4_get_mtu_info(skb, info) :
				    quic_v6_get_mtu_info(skb, info);
}

#define quic_pf_ipv4(sk)	((sk)->sk_family == PF_INET)

bool quic_cmp_sk_addr(struct sock *sk, union quic_addr *a,
		      union quic_addr *addr)
{
	return quic_pf_ipv4(sk) ? quic_v4_cmp_sk_addr(sk, a, addr) :
				  quic_v6_cmp_sk_addr(sk, a, addr);
}

int quic_get_sk_addr(struct socket *sock, struct sockaddr *a, int peer)
{
	return quic_pf_ipv4(sock->sk) ? quic_v4_get_sk_addr(sock, a, peer) :
					quic_v6_get_sk_addr(sock, a, peer);
}

int quic_get_dev_if(struct sock *sk, union quic_addr *a)
{
	if (!quic_af_ipv4(a) &&
	    ipv6_addr_type(&a->v6.sin6_addr) & IPV6_ADDR_LINKLOCAL &&
	    a->v6.sin6_scope_id)
		return a->v6.sin6_scope_id;

	return sk->sk_bound_dev_if;
}

void quic_set_skb_iif(struct sk_buff *skb)
{
	/* Save the inet/inet6 iif before skb dst/cb are cleared. */
	skb->skb_iif = quic_skb_ipv4(skb) ? inet_iif(skb) : inet6_iif(skb);
}

int quic_common_setsockopt(struct sock *sk, int level, int optname,
			   sockptr_t optval, unsigned int optlen)
{
	return quic_pf_ipv4(sk) ?
	       ip_setsockopt(sk, level, optname, optval, optlen) :
	       ipv6_setsockopt(sk, level, optname, optval, optlen);
}

int quic_common_getsockopt(struct sock *sk, int level, int optname,
			   char __user *optval, int __user *optlen)
{
	return quic_pf_ipv4(sk) ?
	       ip_getsockopt(sk, level, optname, optval, optlen) :
	       ipv6_getsockopt(sk, level, optname, optval, optlen);
}

bool quic_sk_accept_pmtu(struct sock *sk, struct sk_buff *skb)
{
	return quic_skb_ipv4(skb) ? ip_sk_accept_pmtu(sk) :
				    ip6_sk_accept_pmtu(sk);
}

void quic_sk_destruct(struct sock *sk)
{
	quic_pf_ipv4(sk) ? inet_sock_destruct(sk) : inet6_sock_destruct(sk);
}
