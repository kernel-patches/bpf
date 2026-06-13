// SPDX-License-Identifier: GPL-2.0
/* Copyright 2026 Google LLC */

#include <sys/epoll.h>
#include <net/if.h>
#include <linux/errqueue.h>
#include <linux/net_tstamp.h>

#include "test_progs.h"
#include <network_helpers.h>
#include "proxy_hwtstamp.skel.h"

#define swap(a, b)				\
	do {					\
		typeof(a) __tmp = (a);		\
		(a) = (b);			\
		(b) = __tmp;			\
	} while (0)

#define swap_array(a, b)			\
	do {					\
		char __tmp[sizeof(a)];		\
		memcpy(__tmp, a, sizeof(a));	\
		memcpy(a, b, sizeof(a));	\
		memcpy(b, __tmp, sizeof(a));	\
	} while (0)

struct genevehdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	u8 opt_len:6;
	u8 ver:2;
	u8 rsvd1:6;
	u8 critical:1;
	u8 oam:1;
#else
	u8 ver:2;
	u8 opt_len:6;
	u8 oam:1;
	u8 critical:1;
	u8 rsvd1:6;
#endif
	__be16 proto_type;
	u8 vni[3];
	u8 rsvd2;
};

struct geneve_opt {
	__be16	opt_class;
	u8	type;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	u8	length:5;
	u8	r3:1;
	u8	r2:1;
	u8	r1:1;
#else
	u8	r1:1;
	u8	r2:1;
	u8	r3:1;
	u8	length:5;
#endif
};

struct proxy_header {
	struct genevehdr geneve;
	struct geneve_opt geneve_opt;
	s64 hwtstamp;
	u32 tskey;
	struct ethhdr eth;
	union {
		struct {
			struct iphdr ip;
			struct udphdr udp;
		} v4;
		struct {
			struct ipv6hdr ip;
			struct udphdr udp;
		} v6;
	};
} __attribute__((packed));

#define GENEVE_VNI		0x900913
#define GENEVE_OPT_CLASS	0x9009
#define GENEVE_OPT_LEN		((sizeof(struct proxy_hwtstamp_opt)	\
				  - sizeof(struct geneve_opt)) / 4)
enum {
	GENEVE_OPT_TYPE_TX	= 1,
	GENEVE_OPT_TYPE_TX_CMPL	= 2,
	GENEVE_OPT_TYPE_RX	= 3,
};

#define APP_DST_IPV4		"192.168.0.1"
#define APP_DST_IPV6		"2001:db7::92"

#define GENEVE_PORT		6081
#define APP_SRC_IPV4		"10.0.3.1"
#define APP_SRC_IPV6		"2001:db8::1"

#define HWTSTAMP		0x12345678
#define TSKEY			0xaabbccdd

static struct proxy_hwtstamp_test_case {
	char name[8];
	int family;
	char geneve_remote_ip[16];
	char geneve_local_ip[16];
	char app_dst_ip[16];
	int app_dst_port;
	int encap_payload_len;

	/* fields below are populated during test. */
	struct proxy_hwtstamp *skel;
	struct netns_obj *netns;
	struct sockaddr_storage geneve_remote_addr;
	struct sockaddr_storage geneve_local_addr;
	socklen_t addrlen;
	int proxy_fd;
	int app_fd;
#define APP_PAYLOAD_LEN		512
	char app_payload[APP_PAYLOAD_LEN];
	char encap_payload[APP_PAYLOAD_LEN + sizeof(struct proxy_header)];
} test_cases[] = {
	{
		.name = "IPv4",
		.family = AF_INET,
		.geneve_remote_ip = "127.0.0.1",
		.geneve_local_ip = APP_SRC_IPV4,
		.app_dst_ip = APP_DST_IPV4,
		.app_dst_port = 443,
		.encap_payload_len = APP_PAYLOAD_LEN + offsetofend(struct proxy_header, v4),
	},
	{
		.name = "IPv6",
		.family = AF_INET6,
		.geneve_remote_ip = "::1",
		.geneve_local_ip = APP_SRC_IPV6,
		.app_dst_ip = APP_DST_IPV6,
		.app_dst_port = 443,
		.encap_payload_len = APP_PAYLOAD_LEN + offsetofend(struct proxy_header, v6),
	},
};

char *ipv4_commands[] = {
	"ip link set dev lo up",
	"ip link add geneve0 type geneve local " APP_SRC_IPV4 " external",
	"ip addr add " APP_SRC_IPV4 "/24 dev geneve0",
	"ip link set dev geneve0 address aa:bb:cc:dd:ee:ff",
	"ip link set dev geneve0 up",
	"ip route add " APP_DST_IPV4 "/32 dev geneve0",
	/*
	 * We do not forward ARP to the wire in this test,
	 * so a static neighbour entry is needed for APP_DST_IPV4.
	 */
	"ip neigh add " APP_DST_IPV4 " lladdr ab:bc:cd:de:ef:fa dev geneve0",
};

char *ipv6_commands[] = {
	"ip link set dev lo up",
	"ip link add geneve0 type geneve local " APP_SRC_IPV6 " external",
	"ip -6 addr add " APP_SRC_IPV6 "/32 dev geneve0 nodad",
	"ip link set dev geneve0 address aa:bb:cc:dd:ee:ff",
	"ip link set dev geneve0 up",
	"ip -6 route add " APP_DST_IPV6 "/128 dev geneve0",
	/* Similarly, APP_DST_IPV6 needs a static neighbour entry */
	"ip -6 neigh add " APP_DST_IPV6 " lladdr ab:bc:cd:de:ef:fa dev geneve0",
};

static int setup_netns(struct proxy_hwtstamp_test_case *test_case)
{
	int i, array_size, ret;
	char **commands;

	if (test_case->family == AF_INET) {
		commands = ipv4_commands;
		array_size = ARRAY_SIZE(ipv4_commands);
	} else {
		commands = ipv6_commands;
		array_size = ARRAY_SIZE(ipv6_commands);
	}

	for (i = 0; i < array_size; i++) {
		ret = system(commands[i]);
		if (!ASSERT_OK(ret, commands[i]))
			break;
	}

	return ret;
}

static int setup_tcx(struct proxy_hwtstamp_test_case *test_case)
{
	struct proxy_hwtstamp *skel = test_case->skel;
	LIBBPF_OPTS(bpf_tcx_opts, tcx_opts_ingress);
	LIBBPF_OPTS(bpf_tcx_opts, tcx_opts_egress);
	struct bpf_link *link;
	int ifindex;

	ifindex = if_nametoindex("geneve0");

	if (make_sockaddr(test_case->family, test_case->geneve_remote_ip, GENEVE_PORT,
			  &test_case->geneve_remote_addr, &test_case->addrlen))
		goto err;

	if (make_sockaddr(test_case->family, test_case->geneve_local_ip, GENEVE_PORT,
			  &test_case->geneve_local_addr, &test_case->addrlen))
		goto err;

	/*
	 * Set up struct bpf_tunnel_key for GENEVE.
	 * Note that bpf_skb_set_tunnel_key() expects
	 *   IPv4 address in host byte order
	 *   IPv6 address in network byte order.
	 */
	skel->bss->key_dst.tunnel_id = GENEVE_VNI;
	if (test_case->family == AF_INET) {
		struct sockaddr_in *addr4;

		addr4 = (struct sockaddr_in *)&test_case->geneve_remote_addr;
		skel->bss->key_dst.remote_ipv4 = ntohl(addr4->sin_addr.s_addr);

		addr4 = (struct sockaddr_in *)&test_case->geneve_local_addr;
		skel->bss->key_dst.local_ipv4 = ntohl(addr4->sin_addr.s_addr);

		skel->bss->tunnel_tx_flags = BPF_F_ZERO_CSUM_TX;
		skel->bss->tunnel_rx_flags = 0;
	} else {
		struct sockaddr_in6 *addr6;

		addr6 = (struct sockaddr_in6 *)&test_case->geneve_remote_addr;
		memcpy(&skel->bss->key_dst.remote_ipv6,
		       &addr6->sin6_addr, sizeof(addr6->sin6_addr));

		addr6 = (struct sockaddr_in6 *)&test_case->geneve_local_addr;
		memcpy(&skel->bss->key_dst.local_ipv6,
		       &addr6->sin6_addr, sizeof(addr6->sin6_addr));

		/*
		 * IPv6 requires BPF_F_TUNINFO_IPV6.
		 * Since udpv6_rcv() drops 0 csum packets unlike udp_rcv()
		 * by default, UDP_NO_CHECK6_RX must be set on the proxy socket.
		 */
		skel->bss->tunnel_tx_flags = BPF_F_ZERO_CSUM_TX | BPF_F_TUNINFO_IPV6;
		skel->bss->tunnel_rx_flags = BPF_F_TUNINFO_IPV6;
	}

	/* Attach BPF progs to egress and ingress. */
	link = bpf_program__attach_tcx(skel->progs.proxy_hwtstamp_ingress,
				       ifindex, &tcx_opts_ingress);
	if (!ASSERT_OK_PTR(link, "attach_tcx(ingress)"))
		goto err;

	skel->links.proxy_hwtstamp_ingress = link;

	link = bpf_program__attach_tcx(skel->progs.proxy_hwtstamp_egress,
				       ifindex, &tcx_opts_egress);
	if (!ASSERT_OK_PTR(link, "attach_tcx(egress)"))
		goto err;

	skel->links.proxy_hwtstamp_egress = link;

	return 0;
err:
	return -1;
}

static int setup_fd(struct proxy_hwtstamp_test_case *test_case)
{
	int proxy_fd, app_fd;
	int val, ret;

	proxy_fd = start_server_addr(SOCK_DGRAM, &test_case->geneve_remote_addr,
				     test_case->addrlen, NULL);
	if (!ASSERT_OK_FD(proxy_fd, "start_server"))
		goto err;

	if (test_case->family == AF_INET6) {
		/*
		 * udpv6_rcv() drops 0 csum (BPF_F_ZERO_CSUM_TX) packets
		 * unless UDP_NO_CHECK6_RX is set.
		 */
		val = 1;
		ret = setsockopt(proxy_fd, SOL_UDP, UDP_NO_CHECK6_RX, &val, sizeof(val));
		if (!ASSERT_OK(ret, "setsockopt(UDP_NO_CHECK6_RX)"))
			goto close_proxy;
	}

	app_fd = connect_to_addr_str(test_case->family, SOCK_DGRAM,
				     test_case->app_dst_ip,
				     test_case->app_dst_port, NULL);
	if (!ASSERT_OK_FD(app_fd, "connect_to_addr_str"))
		goto close_proxy;

	val = SOF_TIMESTAMPING_RX_HARDWARE |
	      SOF_TIMESTAMPING_TX_HARDWARE |
	      SOF_TIMESTAMPING_RAW_HARDWARE |
	      SOF_TIMESTAMPING_OPT_ID;
	ret = setsockopt(app_fd, SOL_SOCKET, SO_TIMESTAMPING_NEW, &val, sizeof(val));
	if (!ASSERT_OK(ret, "setsockopt(SO_TIMESTAMPING_NEW)"))
		goto close_app;

	test_case->proxy_fd = proxy_fd;
	test_case->app_fd = app_fd;

	return 0;

close_app:
	close(app_fd);
close_proxy:
	close(proxy_fd);
err:
	return -1;
}

static void destroy_env(struct proxy_hwtstamp_test_case *test_case)
{
	close(test_case->app_fd);
	close(test_case->proxy_fd);
	proxy_hwtstamp__destroy(test_case->skel);
	netns_free(test_case->netns);
}

static int setup_env(struct proxy_hwtstamp_test_case *test_case)
{
	test_case->netns = netns_new("proxy_hwtstamp", true);
	if (!ASSERT_OK_PTR(test_case->netns, "netns_new"))
		goto err;

	if (setup_netns(test_case))
		goto free_netns;

	test_case->skel = proxy_hwtstamp__open_and_load();
	if (!ASSERT_OK_PTR(test_case->skel, "open_and_load"))
		goto free_netns;

	if (setup_tcx(test_case))
		goto destroy_skel;

	if (setup_fd(test_case))
		goto destroy_skel;

	return 0;

destroy_skel:
	proxy_hwtstamp__destroy(test_case->skel);
free_netns:
	netns_free(test_case->netns);
err:
	return -1;
}

static int wait_data(struct proxy_hwtstamp_test_case *test_case, bool tx)
{
	struct epoll_event event = {
		.events = tx ? EPOLLERR : EPOLLIN,
		.data.fd = test_case->app_fd,
	};
	int epoll_fd;
	int ret = -1;

	epoll_fd = epoll_create1(0);
	if (!ASSERT_GE(epoll_fd, 0, "epoll_create1"))
		goto out;

	ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, test_case->app_fd, &event);
	if (!ASSERT_OK(ret, "epoll_ctl"))
		goto close_epoll;

	ret = epoll_wait(epoll_fd, &event, 1, 3000);
	if (ASSERT_EQ(ret, 1, "epoll_wait"))
		ret = 0;
	else
		ret = -1;

close_epoll:
	close(epoll_fd);
out:
	return ret;
}

static int check_tstamp(struct proxy_hwtstamp_test_case *test_case, bool tx)
{
	char buf_msg[APP_PAYLOAD_LEN * 2], buf_cmsg[1024];
	bool saw_tstamp = false, saw_tskey = false;
	struct msghdr msg = {};
	struct iovec iov = {};
	struct cmsghdr *cmsg;
	int ret;

	if (wait_data(test_case, tx))
		return -1;

	iov.iov_base = buf_msg;
	iov.iov_len = sizeof(buf_msg);

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = buf_cmsg;
	msg.msg_controllen = sizeof(buf_cmsg);

	ret = recvmsg(test_case->app_fd, &msg, tx ? MSG_ERRQUEUE : 0);

	if (ret > 0)
		hexdump(tx ? "tx tstamp  " : "rx tstamp  ", buf_msg, ret);

	if (!ASSERT_EQ(ret, APP_PAYLOAD_LEN, "recvmsg"))
		return -1;

	ret = memcmp(buf_msg, test_case->app_payload, sizeof(test_case->app_payload));
	ASSERT_OK(ret, "memcmp");

	ret = -1;

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_TIMESTAMPING_NEW) {
			struct scm_timestamping64 *ts;

			ts = (struct scm_timestamping64 *)CMSG_DATA(cmsg);
			ASSERT_EQ(ts->ts[2].tv_sec, 0, "tv_sec");
			ASSERT_EQ(ts->ts[2].tv_nsec, HWTSTAMP, "tv_nsec");

			saw_tstamp = true;
		} else if ((cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_RECVERR) ||
			   (cmsg->cmsg_level == SOL_IPV6 && cmsg->cmsg_type == IPV6_RECVERR)) {
			struct sock_extended_err *ee;

			ee = (struct sock_extended_err *)CMSG_DATA(cmsg);

			if (ee->ee_origin == SO_EE_ORIGIN_TIMESTAMPING) {
				ASSERT_EQ(ee->ee_data, TSKEY, "tskey");
				saw_tskey = true;
			}
		}
	}

	ASSERT_TRUE(saw_tstamp && (!tx || saw_tskey), "no timestamp");

	return ret;
}

static int test_proxy_hwtstamp_tx(struct proxy_hwtstamp_test_case *test_case)
{
	char h_source_dummy[ETH_HLEN] = {0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA};
	char buf_cmsg[CMSG_SPACE(sizeof(u32))];
	struct proxy_header *phdr;
	struct msghdr msg = {};
	struct iovec iov = {};
	struct cmsghdr *cmsg;
	int ret;

	memset(test_case->app_payload, 0xAB, sizeof(test_case->app_payload));
	iov.iov_base = test_case->app_payload;
	iov.iov_len = sizeof(test_case->app_payload);

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = buf_cmsg;
	msg.msg_controllen = sizeof(buf_cmsg);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_TS_OPT_ID;
	cmsg->cmsg_len = CMSG_LEN(sizeof(u32));
	*(u32 *)CMSG_DATA(cmsg) = TSKEY;

	ret = sendmsg(test_case->app_fd, &msg, 0);
	if (!ASSERT_EQ(ret, sizeof(test_case->app_payload), "send"))
		return -1;

	while (1) {
		memset(test_case->encap_payload, 0, sizeof(test_case->encap_payload));

		ret = recv(test_case->proxy_fd, test_case->encap_payload,
			   sizeof(test_case->encap_payload), 0);
		if (ret <= (int)sizeof(phdr->geneve)) {
			ASSERT_GT(ret, (int)sizeof(phdr->geneve), "recv(tx ingress)");
			return -1;
		}

		phdr = (struct proxy_header *)test_case->encap_payload;

		/*
		 * In the real world, we forward all packets,
		 * including ARP, NDP, etc, but now we ignore them.
		 * In this test case, we only care about skb with
		 * the GENEVE option, meaning it was sent by app_fd.
		 */
		if (phdr->geneve.opt_len)
			break;
	}

	hexdump("tx payload ", test_case->encap_payload,
		test_case->encap_payload_len);

	if (!ASSERT_EQ(ret, test_case->encap_payload_len, "encap payload len"))
		return -1;

	if (!ASSERT_EQ(phdr->tskey, TSKEY, "tskey"))
		return -1;

	/*
	 * Assume we have got TX hwtstamp now.
	 * Reuse the original payload to "regenerate" the
	 * same skb to put into app_fd's sk_error_queue.
	 */
	phdr->geneve_opt.type = GENEVE_OPT_TYPE_TX_CMPL;
	phdr->hwtstamp = HWTSTAMP;

	/*
	 * GENEVE drops a packet if the outer/inner eth headers
	 * have the same source address. (See geneve_rx())
	 * Work around it by filling a fake address.
	 */
	swap_array(phdr->eth.h_source, h_source_dummy);

	/* Send the TX completion packet to geneve0. */
	ret = sendto(test_case->proxy_fd,
		     test_case->encap_payload, test_case->encap_payload_len, 0,
		     (struct sockaddr *)&test_case->geneve_local_addr, test_case->addrlen);
	if (!ASSERT_EQ(ret, test_case->encap_payload_len, "sendto(tx cmpl)"))
		return -1;

	swap_array(phdr->eth.h_source, h_source_dummy);

	return check_tstamp(test_case, true);
}

static int test_proxy_hwtstamp_rx(struct proxy_hwtstamp_test_case *test_case)
{
	struct proxy_header *phdr;
	int ret;

	/*
	 * Assume we have received a packet w/ RX hwtstamp.
	 * Generate RX packet by swapping source/dest of the
	 * original TX packet.
	 */
	phdr = (struct proxy_header *)test_case->encap_payload;

	swap_array(phdr->eth.h_dest, phdr->eth.h_source);

	if (test_case->family == AF_INET) {
		swap(phdr->v4.ip.daddr, phdr->v4.ip.saddr);
		swap(phdr->v4.udp.dest, phdr->v4.udp.source);
	} else {
		swap(phdr->v6.ip.daddr, phdr->v6.ip.saddr);
		swap(phdr->v6.udp.dest, phdr->v6.udp.source);
	}

	/* Embed RX hwtstamp into the GENEVE option. */
	phdr->geneve_opt.type = GENEVE_OPT_TYPE_RX;
	phdr->hwtstamp = HWTSTAMP;
	phdr->tskey = 0;

	/* Send the packet to geneve0. */
	ret = sendto(test_case->proxy_fd,
		     test_case->encap_payload, test_case->encap_payload_len, 0,
		     (struct sockaddr *)&test_case->geneve_local_addr, test_case->addrlen);
	if (!ASSERT_EQ(ret, test_case->encap_payload_len, "sendto(rx)"))
		return -1;

	return check_tstamp(test_case, false);
}

static void run_test(struct proxy_hwtstamp_test_case *test_case)
{
	int ret;

	ret = setup_env(test_case);
	if (ret)
		return;

	ret = test_proxy_hwtstamp_tx(test_case);
	if (!ret)
		test_proxy_hwtstamp_rx(test_case);

	destroy_env(test_case);
}

void test_proxy_hwtstamp(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(test_cases); i++) {
		if (!test__start_subtest(test_cases[i].name))
			continue;

		run_test(&test_cases[i]);
	}
}
