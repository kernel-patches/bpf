// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>
#include "xdp_metadata.skel.h"
#include "xsk.h"

#include <linux/errqueue.h>
#include <linux/if_link.h>
#include <linux/net_tstamp.h>
#include <linux/udp.h>
#include <sys/mman.h>
#include <net/if.h>
#include <poll.h>

#define TX_NAME "veTX"
#define RX_NAME "veRX"

#define UDP_PAYLOAD_BYTES 4

#define AF_XDP_SOURCE_PORT 1234
#define AF_XDP_CONSUMER_PORT 8080
#define SOCKET_CONSUMER_PORT 9081

#ifndef SOL_UDP
#define SOL_UDP		17
#endif

#define UMEM_NUM 16
#define UMEM_FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE
#define UMEM_SIZE (UMEM_FRAME_SIZE * UMEM_NUM)
#define XDP_FLAGS XDP_FLAGS_DRV_MODE
#define QUEUE_ID 0

#define TX_ADDR "10.0.0.1"
#define RX_ADDR "10.0.0.2"
#define PREFIX_LEN "8"
#define FAMILY AF_INET

#define SYS(cmd) ({ \
	if (!ASSERT_OK(system(cmd), (cmd))) \
		goto out; \
})

struct xsk {
	void *umem_area;
	struct xsk_umem *umem;
	struct xsk_ring_prod fill;
	struct xsk_ring_cons comp;
	struct xsk_ring_prod tx;
	struct xsk_ring_cons rx;
	struct xsk_socket *socket;
	int next_tx;
};

int open_xsk(const char *ifname, struct xsk *xsk)
{
	int mmap_flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE;
	const struct xsk_socket_config socket_config = {
		.rx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
		.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
		.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
		.xdp_flags = XDP_FLAGS,
		.bind_flags = XDP_COPY,
	};
	u64 addr;
	int ret;
	int i;

	xsk->umem_area = mmap(NULL, UMEM_SIZE, PROT_READ | PROT_WRITE, mmap_flags, -1, 0);
	if (!ASSERT_NEQ(xsk->umem_area, MAP_FAILED, "mmap"))
		return -1;

	ret = xsk_umem__create(&xsk->umem,
			       xsk->umem_area, UMEM_SIZE,
			       &xsk->fill,
			       &xsk->comp,
			       NULL);
	if (!ASSERT_OK(ret, "xsk_umem__create"))
		return ret;

	ret = xsk_socket__create(&xsk->socket, ifname, QUEUE_ID,
				 xsk->umem,
				 &xsk->rx,
				 &xsk->tx,
				 &socket_config);
	if (!ASSERT_OK(ret, "xsk_socket__create"))
		return ret;

	/* First half of umem is for TX. This way address matches 1-to-1
	 * to the completion queue index.
	 */

	xsk->next_tx = 0;

	/* Second half of umem is for RX. */

	__u32 idx;
	ret = xsk_ring_prod__reserve(&xsk->fill, UMEM_NUM / 2, &idx);
	if (!ASSERT_EQ(UMEM_NUM / 2, ret, "xsk_ring_prod__reserve"))
		return ret;
	if (!ASSERT_EQ(idx, 0, "fill idx != 0"))
		return -1;

	for (i = 0; i < UMEM_NUM / 2; i++) {
		addr = (UMEM_NUM / 2 + i) * UMEM_FRAME_SIZE;
		*xsk_ring_prod__fill_addr(&xsk->fill, i) = addr;
	}
	xsk_ring_prod__submit(&xsk->fill, ret);

	return 0;
}

void close_xsk(struct xsk *xsk)
{
	if (xsk->umem)
		xsk_umem__delete(xsk->umem);
	if (xsk->socket)
		xsk_socket__delete(xsk->socket);
	munmap(xsk->umem, UMEM_SIZE);
}

static void ip_csum(struct iphdr *iph)
{
	__u32 sum = 0;
	__u16 *p;
	int i;

	iph->check = 0;
	p = (void *)iph;
	for (i = 0; i < sizeof(*iph) / sizeof(*p); i++)
		sum += p[i];

	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	iph->check = ~sum;
}

int generate_packet(struct xsk *xsk, __u16 dst_port)
{
	struct xdp_desc *tx_desc;
	struct udphdr *udph;
	struct ethhdr *eth;
	struct iphdr *iph;
	void *data;
	__u32 idx;
	int ret;

	ret = xsk_ring_prod__reserve(&xsk->tx, 1, &idx);
	if (!ASSERT_EQ(ret, 1, "xsk_ring_prod__reserve"))
		return -1;

	tx_desc = xsk_ring_prod__tx_desc(&xsk->tx, idx);
	tx_desc->addr = xsk->next_tx++ % (UMEM_NUM / 2);
	data = xsk_umem__get_data(xsk->umem_area, tx_desc->addr);

	eth = data;
	iph = (void *)(eth + 1);
	udph = (void *)(iph + 1);

	memcpy(eth->h_dest, "\x00\x00\x00\x00\x00\x02", ETH_ALEN);
	memcpy(eth->h_source, "\x00\x00\x00\x00\x00\x01", ETH_ALEN);
	eth->h_proto = htons(ETH_P_IP);

	iph->version = 0x4;
	iph->ihl = 0x5;
	iph->tos = 0x9;
	iph->tot_len = htons(sizeof(*iph) + sizeof(*udph) + UDP_PAYLOAD_BYTES);
	iph->id = 0;
	iph->frag_off = 0;
	iph->ttl = 0;
	iph->protocol = IPPROTO_UDP;
	ASSERT_EQ(inet_pton(FAMILY, TX_ADDR, &iph->saddr), 1, "inet_pton(TX_ADDR)");
	ASSERT_EQ(inet_pton(FAMILY, RX_ADDR, &iph->daddr), 1, "inet_pton(RX_ADDR)");
	ip_csum(iph);

	udph->source = htons(AF_XDP_SOURCE_PORT);
	udph->dest = htons(dst_port);
	udph->len = htons(sizeof(*udph) + UDP_PAYLOAD_BYTES);
	udph->check = 0;

	memset(udph + 1, 0xAA, UDP_PAYLOAD_BYTES);

	tx_desc->len = sizeof(*eth) + sizeof(*iph) + sizeof(*udph) + UDP_PAYLOAD_BYTES;
	xsk_ring_prod__submit(&xsk->tx, 1);

	ret = sendto(xsk_socket__fd(xsk->socket), NULL, 0, MSG_DONTWAIT, NULL, 0);
	if (!ASSERT_GE(ret, 0, "sendto"))
		return ret;

	return 0;
}

int verify_xsk_metadata(struct xsk *xsk)
{
	const struct xdp_desc *rx_desc;
	struct pollfd fds = {};
	void *data_meta;
	void *data;
	__u32 idx;
	int ret;

	ret = recvfrom(xsk_socket__fd(xsk->socket), NULL, 0, MSG_DONTWAIT, NULL, NULL);
	if (!ASSERT_EQ(ret, 0, "recvfrom"))
		return -1;

	fds.fd = xsk_socket__fd(xsk->socket);
	fds.events = POLLIN;

	ret = poll(&fds, 1, 1000);
	if (!ASSERT_GT(ret, 0, "poll"))
		return -1;

	ret = xsk_ring_cons__peek(&xsk->rx, 1, &idx);
	if (!ASSERT_EQ(ret, 1, "xsk_ring_cons__peek"))
		return -2;

	rx_desc = xsk_ring_cons__rx_desc(&xsk->rx, idx++);
	data = xsk_umem__get_data(xsk->umem_area, rx_desc->addr);

	data_meta = data - 8; /* oh boy, this seems wrong! */

	if (*(__u32 *)data_meta == 0)
		return -1;

	return 0;
}

static void disable_rx_checksum(int fd)
{
	int ret, val;

	val = 1;
	ret = setsockopt(fd, SOL_UDP, UDP_NO_CHECK6_RX, &val, sizeof(val));
	ASSERT_OK(ret, "setsockopt(UDP_NO_CHECK6_RX)");
}

static void timestamping_enable(int fd)
{
	int ret, val;

	val = SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_RAW_HARDWARE;
	ret = setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPING, &val, sizeof(val));
	ASSERT_OK(ret, "setsockopt(SO_TIMESTAMPING)");
}

int verify_skb_metadata(int fd)
{
	char cmsg_buf[1024];
	char packet_buf[128];

	struct scm_timestamping *ts;
	struct iovec packet_iov;
	struct cmsghdr *cmsg;
	struct msghdr hdr;
	bool found_hwtstamp = false;

	memset(&hdr, 0, sizeof(hdr));
	hdr.msg_iov = &packet_iov;
	hdr.msg_iovlen = 1;
	packet_iov.iov_base = packet_buf;
	packet_iov.iov_len = sizeof(packet_buf);

	hdr.msg_control = cmsg_buf;
	hdr.msg_controllen = sizeof(cmsg_buf);

	if (ASSERT_GE(recvmsg(fd, &hdr, 0), 0, "recvmsg")) {
		for (cmsg = CMSG_FIRSTHDR(&hdr); cmsg != NULL;
		     cmsg = CMSG_NXTHDR(&hdr, cmsg)) {

			if (cmsg->cmsg_level != SOL_SOCKET)
				continue;

			switch (cmsg->cmsg_type) {
			case SCM_TIMESTAMPING:
				ts = (struct scm_timestamping *)CMSG_DATA(cmsg);
				if (ts->ts[2].tv_sec || ts->ts[2].tv_nsec) {
					found_hwtstamp = true;
					break;
				}
				break;
			default:
				break;
			}
		}
	}

	if (!ASSERT_EQ(found_hwtstamp, true, "no hwtstamp!"))
		return -1;

	return 0;
}

void test_xdp_metadata(void)
{
	struct xdp_metadata *bpf_obj = NULL;
	struct nstoken *tok = NULL;
	struct bpf_program *prog;
	struct xsk tx_xsk = {};
	struct xsk rx_xsk = {};
	int rx_udp_fd = -1;
	int rx_ifindex;
	int ret;

	/* Setup new networking namespace, with a veth pair. */

	SYS("ip netns add xdp_metadata");
	tok = open_netns("xdp_metadata");
	SYS("ip link add numtxqueues 1 numrxqueues 1 " TX_NAME " type veth "
	    "peer " RX_NAME " numtxqueues 1 numrxqueues 1");
	SYS("ip link set dev " TX_NAME " address 00:00:00:00:00:01");
	SYS("ip link set dev " RX_NAME " address 00:00:00:00:00:02");
	SYS("ip link set dev " TX_NAME " up");
	SYS("ip link set dev " RX_NAME " up");
	SYS("ip addr add " TX_ADDR "/" PREFIX_LEN " dev " TX_NAME);
	SYS("ip addr add " RX_ADDR "/" PREFIX_LEN " dev " RX_NAME);
	SYS("sysctl -q net.ipv4.ip_forward=1");
	SYS("sysctl -q net.ipv4.conf.all.accept_local=1");

	rx_ifindex = if_nametoindex(RX_NAME);

	/* Setup separate AF_XDP for TX and RX interfaces. */

	ret = open_xsk(TX_NAME, &tx_xsk);
	if (!ASSERT_OK(ret, "open_xsk(TX_NAME)"))
		goto out;

	ret = open_xsk(RX_NAME, &rx_xsk);
	if (!ASSERT_OK(ret, "open_xsk(RX_NAME)"))
		goto out;

	/* Setup UPD listener for RX interface. */

	rx_udp_fd = start_server(FAMILY, SOCK_DGRAM, NULL, SOCKET_CONSUMER_PORT, 1000);
	if (!ASSERT_GE(rx_udp_fd, 0, "start_server"))
		goto out;
	disable_rx_checksum(rx_udp_fd);
	timestamping_enable(rx_udp_fd);

	/* Attach BPF program to RX interface. */

	bpf_obj = xdp_metadata__open();
	if (!ASSERT_OK_PTR(bpf_obj, "open skeleton"))
		goto out;

	prog = bpf_object__find_program_by_name(bpf_obj->obj, "rx");
	bpf_program__set_ifindex(prog, rx_ifindex);
	bpf_program__set_flags(prog, BPF_F_XDP_HAS_METADATA);

	if (!ASSERT_OK(xdp_metadata__load(bpf_obj), "load skeleton"))
		goto out;

	ret = bpf_xdp_attach(rx_ifindex,
			     bpf_program__fd(bpf_obj->progs.rx),
			     XDP_FLAGS, NULL);
	if (!ASSERT_GE(ret, 0, "bpf_xdp_attach"))
		goto out;

	__u32 queue_id = QUEUE_ID;
	int sock_fd = xsk_socket__fd(rx_xsk.socket);
	ret = bpf_map_update_elem(bpf_map__fd(bpf_obj->maps.xsk), &queue_id, &sock_fd, 0);
	if (!ASSERT_GE(ret, 0, "bpf_map_update_elem"))
		goto out;

	/* Send packet destined to RX AF_XDP socket. */
	if (!ASSERT_GE(generate_packet(&tx_xsk, AF_XDP_CONSUMER_PORT), 0,
		       "generate AF_XDP_CONSUMER_PORT"))
	    goto out;

	/* Verify AF_XDP RX packet has proper metadata. */
	if (!ASSERT_GE(verify_xsk_metadata(&rx_xsk), 0,
		       "verify_xsk_metadata"))
	    goto out;

	/* Send packet destined to RX UDP socket. */
	if (!ASSERT_GE(generate_packet(&tx_xsk, SOCKET_CONSUMER_PORT), 0,
		       "generate SOCKET_CONSUMER_PORT"))
	    goto out;

	/* Verify SKB RX packet has proper metadata. */
	if (!ASSERT_GE(verify_skb_metadata(rx_udp_fd), 0,
		       "verify_skb_metadata"))
	    goto out;

out:
	close_xsk(&rx_xsk);
	close_xsk(&tx_xsk);
	close(rx_udp_fd);
	if (bpf_obj)
		xdp_metadata__destroy(bpf_obj);
	system("ip netns del xdp_metadata");
	if (tok)
		close_netns(tok);
}
