// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE

#include <net/if.h>
#include <sched.h>

#include "test_progs.h"
#include "vnet_hash.skel.h"

#include <linux/if_arp.h>
#include <linux/if_tun.h>
#include <linux/sockios.h>
#include <linux/virtio_net.h>

#define TUN_HWADDR_SOURCE { 0x02, 0x00, 0x00, 0x00, 0x00, 0x00 }
#define TUN_HWADDR_DEST { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 }

#define TUN_IPADDR_SOURCE htonl((172 << 24) | (17 << 16) | 0)
#define TUN_IPADDR_DEST htonl((172 << 24) | (17 << 16) | 1)

struct payload {
	struct ethhdr ethhdr;
	struct arphdr arphdr;
	unsigned char sender_hwaddr[6];
	uint32_t sender_ipaddr;
	unsigned char target_hwaddr[6];
	uint32_t target_ipaddr;
} __packed;

static bool bpf_setup(struct vnet_hash **skel)
{
	*skel = vnet_hash__open();
	if (!ASSERT_OK_PTR(*skel, __func__))
		return false;

	if (!ASSERT_OK(vnet_hash__load(*skel), __func__)) {
		vnet_hash__destroy(*skel);
		return false;
	}

	return true;
}

static void bpf_teardown(struct vnet_hash *skel)
{
	vnet_hash__destroy(skel);
}

static bool local_setup(int *fd)
{
	*fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	return ASSERT_GE(*fd, 0, __func__);
}

static bool local_set_flags(int fd, const char *name, short flags)
{
	struct ifreq ifreq = { .ifr_flags = flags };

	strcpy(ifreq.ifr_name, name);

	return ASSERT_OK(ioctl(fd, SIOCSIFFLAGS, &ifreq), __func__);
}

static void local_teardown(int fd)
{
	ASSERT_OK(close(fd), __func__);
}

static bool bridge_setup(int local_fd)
{
	if (!ASSERT_OK(ioctl(local_fd, SIOCBRADDBR, "xbridge"), __func__))
		return false;

	return local_set_flags(local_fd, "xbridge", IFF_UP);
}

static bool bridge_add_if(int local_fd, const char *name)
{
	struct ifreq ifreq = {
		.ifr_name = "xbridge",
		.ifr_ifindex = if_nametoindex(name)
	};

	if (!ASSERT_NEQ(ifreq.ifr_ifindex, 0, __func__))
		return false;

	return ASSERT_OK(ioctl(local_fd, SIOCBRADDIF, &ifreq), __func__);
}

static void bridge_teardown(int local_fd)
{
	if (!local_set_flags(local_fd, "xbridge", 0))
		return;

	ASSERT_OK(ioctl(local_fd, SIOCBRDELBR, "xbridge"), __func__);
}

static bool tun_open(int *fd, char *ifname, short flags)
{
	struct ifreq ifr;

	*fd = open("/dev/net/tun", O_RDWR);
	if (!ASSERT_GE(*fd, 0, __func__))
		return false;

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, ifname);
	ifr.ifr_flags = flags | IFF_TAP | IFF_NAPI | IFF_NO_PI |
			IFF_MULTI_QUEUE;

	if (!ASSERT_OK(ioctl(*fd, TUNSETIFF, (void *) &ifr), __func__)) {
		ASSERT_OK(close(*fd), __func__);
		return false;
	}

	strcpy(ifname, ifr.ifr_name);

	return true;
}

static bool tun_source_setup(int local_fd, int *fd)
{
	char ifname[IFNAMSIZ];

	ifname[0] = 0;
	if (!tun_open(fd, ifname, 0))
		return false;

	if (!bridge_add_if(local_fd, ifname)) {
		ASSERT_OK(close(*fd), __func__);
		return false;
	}

	if (!local_set_flags(local_fd, ifname, IFF_UP)) {
		ASSERT_OK(close(*fd), __func__);
		return false;
	}

	return true;
}

static void tun_source_teardown(int fd)
{
	ASSERT_OK(close(fd), __func__);
}

static bool tun_dest_setup(int local_fd, struct vnet_hash *bpf,
			   int *fd, char *ifname)
{
	struct {
		struct virtio_net_hdr vnet_hdr;
		struct payload payload;
	} __packed packet = {
		.payload = {
			.ethhdr = {
				.h_source = TUN_HWADDR_DEST,
				.h_dest = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
				.h_proto = htons(ETH_P_ARP)
			},
			.arphdr = {
				.ar_hrd = htons(ARPHRD_ETHER),
				.ar_pro = htons(ETH_P_IP),
				.ar_hln = ETH_ALEN,
				.ar_pln = 4,
				.ar_op = htons(ARPOP_REQUEST)
			},
			.sender_hwaddr = TUN_HWADDR_DEST,
			.sender_ipaddr = TUN_IPADDR_DEST,
			.target_ipaddr = TUN_IPADDR_DEST
		}
	};

	int bpf_fd = bpf_program__fd(bpf->progs.prog);

	ifname[0] = 0;
	if (!tun_open(fd, ifname, IFF_VNET_HDR))
		return false;

	if (!ASSERT_OK(ioctl(*fd, TUNSETSTEERINGEBPF, &bpf_fd), __func__))
		goto fail;

	if (!bridge_add_if(local_fd, ifname))
		goto fail;

	if (!local_set_flags(local_fd, ifname, IFF_UP))
		goto fail;

	if (!ASSERT_EQ(write(*fd, &packet, sizeof(packet)), sizeof(packet), __func__))
		goto fail;

	return true;

fail:
	ASSERT_OK(close(*fd), __func__);
	return false;
}

static void tun_dest_teardown(int fd)
{
	ASSERT_OK(close(fd), __func__);
}

static bool tun_dest_queue_setup(char *ifname, int *fd)
{
	return tun_open(fd, ifname, IFF_VNET_HDR);
}

static void tun_dest_queue_teardown(int fd)
{
	ASSERT_OK(close(fd), __func__);
}

static void *test_vnet_hash_thread(void *arg)
{
	struct payload sent = {
		.ethhdr = {
			.h_source = TUN_HWADDR_SOURCE,
			.h_dest = TUN_HWADDR_DEST,
			.h_proto = htons(ETH_P_ARP)
		},
		.arphdr = {
			.ar_hrd = htons(ARPHRD_ETHER),
			.ar_pro = htons(ETH_P_IP),
			.ar_hln = ETH_ALEN,
			.ar_pln = 4,
			.ar_op = htons(ARPOP_REPLY)
		},
		.sender_hwaddr = TUN_HWADDR_SOURCE,
		.sender_ipaddr = TUN_IPADDR_SOURCE,
		.target_hwaddr = TUN_HWADDR_DEST,
		.target_ipaddr = TUN_IPADDR_DEST
	};
	union {
		struct virtio_net_hdr_v1_hash virtio_net_hdr;
		uint8_t bytes[sizeof(struct virtio_net_hdr_v1_hash) + sizeof(struct payload)];
	} received;
	struct vnet_hash *bpf;
	int local_fd;
	int source_fd;
	int dest_fds[2];
	char dest_ifname[IFNAMSIZ];
	int vnet_hdr_sz;

	if (!ASSERT_OK(unshare(CLONE_NEWNET), "unshare"))
		return NULL;

	if (!bpf_setup(&bpf))
		return NULL;

	if (!local_setup(&local_fd))
		goto fail_local;

	if (!bridge_setup(local_fd))
		goto fail_bridge;

	if (!tun_source_setup(local_fd, &source_fd))
		goto fail_tun_source;

	if (!tun_dest_setup(local_fd, bpf, dest_fds, dest_ifname))
		goto fail_tun_dest;

	if (!ASSERT_EQ(write(source_fd, &sent, sizeof(sent)), sizeof(sent), "write"))
		goto fail_tests_single_queue;

	if (!ASSERT_EQ(read(dest_fds[0], &received, sizeof(received)),
		       sizeof(struct virtio_net_hdr) + sizeof(struct payload),
		       "read"))
		goto fail_tests_single_queue;

	ASSERT_EQ(received.virtio_net_hdr.hdr.flags, 0,
		  "virtio_net_hdr.hdr.flags");
	ASSERT_EQ(received.virtio_net_hdr.hdr.gso_type, VIRTIO_NET_HDR_GSO_NONE,
		  "virtio_net_hdr.hdr.gso_type");
	ASSERT_EQ(received.virtio_net_hdr.hdr.hdr_len, 0,
		  "virtio_net_hdr.hdr.hdr_len");
	ASSERT_EQ(received.virtio_net_hdr.hdr.gso_size, 0,
		  "virtio_net_hdr.hdr.gso_size");
	ASSERT_EQ(received.virtio_net_hdr.hdr.csum_start, 0,
		  "virtio_net_hdr.hdr.csum_start");
	ASSERT_EQ(received.virtio_net_hdr.hdr.csum_offset, 0,
		  "virtio_net_hdr.hdr.csum_offset");
	ASSERT_EQ(memcmp(received.bytes + sizeof(struct virtio_net_hdr), &sent, sizeof(sent)), 0,
		  "payload");

	vnet_hdr_sz = sizeof(struct virtio_net_hdr_v1_hash);
	if (!ASSERT_OK(ioctl(dest_fds[0], TUNSETVNETHDRSZ, &vnet_hdr_sz), "TUNSETVNETHDRSZ"))
		goto fail_tests_single_queue;

	if (!ASSERT_EQ(write(source_fd, &sent, sizeof(sent)), sizeof(sent),
		       "hash: write"))
		goto fail_tests_single_queue;

	if (!ASSERT_EQ(read(dest_fds[0], &received, sizeof(received)),
		       sizeof(struct virtio_net_hdr_v1_hash) + sizeof(struct payload),
		       "hash: read"))
		goto fail_tests_single_queue;

	ASSERT_EQ(received.virtio_net_hdr.hdr.flags, 0,
		  "hash: virtio_net_hdr.hdr.flags");
	ASSERT_EQ(received.virtio_net_hdr.hdr.gso_type, VIRTIO_NET_HDR_GSO_NONE,
		  "hash: virtio_net_hdr.hdr.gso_type");
	ASSERT_EQ(received.virtio_net_hdr.hdr.hdr_len, 0,
		  "hash: virtio_net_hdr.hdr.hdr_len");
	ASSERT_EQ(received.virtio_net_hdr.hdr.gso_size, 0,
		  "hash: virtio_net_hdr.hdr.gso_size");
	ASSERT_EQ(received.virtio_net_hdr.hdr.csum_start, 0,
		  "hash: virtio_net_hdr.hdr.csum_start");
	ASSERT_EQ(received.virtio_net_hdr.hdr.csum_offset, 0,
		  "hash: virtio_net_hdr.hdr.csum_offset");
	ASSERT_EQ(received.virtio_net_hdr.hdr.num_buffers, 0,
		  "hash: virtio_net_hdr.hdr.num_buffers");
	ASSERT_EQ(received.virtio_net_hdr.hash_value, htole32(3),
		  "hash: virtio_net_hdr.hash_value");
	ASSERT_EQ(received.virtio_net_hdr.hash_report, htole16(2),
		  "hash: virtio_net_hdr.hash_report");
	ASSERT_EQ(received.virtio_net_hdr.padding, 0,
		  "hash: virtio_net_hdr.padding");
	ASSERT_EQ(memcmp(received.bytes + sizeof(struct virtio_net_hdr_v1_hash), &sent,
			 sizeof(sent)),
		  0,
		  "hash: payload");

	if (!tun_dest_queue_setup(dest_ifname, dest_fds + 1))
		goto fail_tests_single_queue;

	if (!ASSERT_EQ(write(source_fd, &sent, sizeof(sent)), sizeof(sent),
		      "hash, multi queue: write"))
		goto fail_tests_multi_queue;

	if (!ASSERT_EQ(read(dest_fds[1], &received, sizeof(received)),
		       sizeof(struct virtio_net_hdr_v1_hash) + sizeof(struct payload),
		       "hash, multi queue: read"))
		goto fail_tests_multi_queue;

	ASSERT_EQ(received.virtio_net_hdr.hdr.flags, 0,
		  "hash, multi queue: virtio_net_hdr.hdr.flags");
	ASSERT_EQ(received.virtio_net_hdr.hdr.gso_type, VIRTIO_NET_HDR_GSO_NONE,
		  "hash, multi queue: virtio_net_hdr.hdr.gso_type");
	ASSERT_EQ(received.virtio_net_hdr.hdr.hdr_len, 0,
		  "hash, multi queue: virtio_net_hdr.hdr.hdr_len");
	ASSERT_EQ(received.virtio_net_hdr.hdr.gso_size, 0,
		  "hash, multi queue: virtio_net_hdr.hdr.gso_size");
	ASSERT_EQ(received.virtio_net_hdr.hdr.csum_start, 0,
		  "hash, multi queue: virtio_net_hdr.hdr.csum_start");
	ASSERT_EQ(received.virtio_net_hdr.hdr.csum_offset, 0,
		  "hash, multi queue: virtio_net_hdr.hdr.csum_offset");
	ASSERT_EQ(received.virtio_net_hdr.hdr.num_buffers, 0,
		  "hash, multi queue: virtio_net_hdr.hdr.num_buffers");
	ASSERT_EQ(received.virtio_net_hdr.hash_value, htole32(3),
		  "hash, multi queue: virtio_net_hdr.hash_value");
	ASSERT_EQ(received.virtio_net_hdr.hash_report, htole16(2),
		  "hash, multi queue: virtio_net_hdr.hash_report");
	ASSERT_EQ(received.virtio_net_hdr.padding, 0,
		  "hash, multi queue: virtio_net_hdr.padding");
	ASSERT_EQ(memcmp(received.bytes + sizeof(struct virtio_net_hdr_v1_hash), &sent,
			 sizeof(sent)),
		  0,
		  "hash, multi queue: payload");

fail_tests_multi_queue:
	tun_dest_queue_teardown(dest_fds[1]);
fail_tests_single_queue:
	tun_dest_teardown(dest_fds[0]);
fail_tun_dest:
	tun_source_teardown(source_fd);
fail_tun_source:
	bridge_teardown(local_fd);
fail_bridge:
	local_teardown(local_fd);
fail_local:
	bpf_teardown(bpf);

	return NULL;
}

void test_vnet_hash(void)
{
	pthread_t thread;
	int err;

	err = pthread_create(&thread, NULL, &test_vnet_hash_thread, NULL);
	if (ASSERT_OK(err, "pthread_create"))
		ASSERT_OK(pthread_join(thread, NULL), "pthread_join");
}
