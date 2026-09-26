// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Simple test to verify the usage of the inline header used for HSR with
 * ether type ETH_P_1588.
 * The inline header has to be stripped, the sent packet must only appear on the
 * specified port and the interface needs to accept a foreign HSR header and
 * prepand its own header.
 *
 * Socket handling inspired by raw.c from linuxptp.
 *
 */
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <linux/if_ether.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>

#define PORT_1	1
#define PORT_2	2

#define MSEC_TO_NSEC(_x)	(_x * 1000000)
#define USEC_PER_SEC		1000000
#define NSEC_PER_SEC		1000000000

#ifndef __packed
#define __packed __attribute__((packed))
#endif

/* HSR Magic */
#define HSR_INLINE_HDR 0xaf485352
struct hsr_inline_header {
	uint8_t tx_port;
	uint8_t hsr_hdr;
	uint8_t __pad0[4];
	uint32_t magic;
	uint8_t __pad1[2];
	uint16_t eth_type;
} __packed;

#define MAC_LEN  6
typedef uint8_t eth_addr[MAC_LEN];

struct eth_hdr {
	eth_addr dst;
	eth_addr src;
	uint16_t type;
} __packed;

struct hsr_hdr {
	eth_addr dst;
	eth_addr src;
	uint16_t type;
	uint16_t pathid_and_LSDU_size;
	uint16_t sequence_nr;
	uint16_t encap_type;
} __packed;

struct hsr_meta_header {
	struct hsr_inline_header hsr_opt;
	union {
		struct hsr_hdr hsr_hdr;
		struct eth_hdr eth_hdr;
	};
} __packed;

static uint8_t ptp_packet[] = {
	0x00, 0x12, 0x00, 0x2c, 0x00, 0x00, 0x02, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x88, 0x88, 0x88, 0x88,  0x88, 0x88, 0x88, 0x88, 0x00, 0x01, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static uint8_t p2p_dst_mac[MAC_LEN] = {
	0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e
};

static uint8_t slave_mac_addr[MAC_LEN];
static int32_t fd_slaveA = -1;
static int32_t fd_slaveB = -1;
static int32_t fd_hsr = -1;
static uint16_t hsr_seq = 37;

static inline void tsnorm(struct timespec *ts)
{
	while (ts->tv_nsec >= NSEC_PER_SEC) {
		ts->tv_nsec -= NSEC_PER_SEC;
		ts->tv_sec++;
	}
}

static inline int64_t calcdiff(struct timespec t1, struct timespec t2)
{
	int64_t diff = USEC_PER_SEC * (long long)((int) t1.tv_sec - (int) t2.tv_sec);

	diff += ((int) t1.tv_nsec - (int) t2.tv_nsec) / 1000;
	return diff;
}

static inline int tsgreater(struct timespec *a, struct timespec *b)
{
	return ((a->tv_sec > b->tv_sec) ||
		(a->tv_sec == b->tv_sec && a->tv_nsec > b->tv_nsec));
}

static int sk_interface_index(int fd, const char *name)
{
	struct ifreq ifreq;
	int32_t err;

	memset(&ifreq, 0, sizeof(ifreq));
	strncpy(ifreq.ifr_name, name, sizeof(ifreq.ifr_name) - 1);
	err = ioctl(fd, SIOCGIFINDEX, &ifreq);
	if (err < 0) {
		printf("ioctl SIOCGIFINDEX failed: %m\n");
		return err;
	}
	return ifreq.ifr_ifindex;
}

static int open_socket(const char *name, uint8_t *local_addr,
		       uint8_t *p2p_dst_mac)
{
	struct sockaddr_ll addr;
	int32_t fd, index;

	fd = socket(AF_PACKET, SOCK_RAW, 0);
	if (fd < 0) {
		printf("socket failed: %m\n");
		goto err;
	}
	index = sk_interface_index(fd, name);
	if (index < 0)
		goto err;

	memset(&addr, 0, sizeof(addr));
	addr.sll_ifindex = index;
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_ALL);
	if (bind(fd, (struct sockaddr *) &addr, sizeof(addr))) {
		printf("bind failed: %m\n");
		goto err;
	}
	if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name))) {
		printf("setsockopt SO_BINDTODEVICE failed: %m\n");
		goto err;
	}

	return fd;
err:
	if (fd >= 0)
		close(fd);
	return -1;
}

static int sk_interface_macaddr(const char *name)
{
	struct ifreq ifreq;
	int32_t err, fd;

	memset(&ifreq, 0, sizeof(ifreq));
	strncpy(ifreq.ifr_name, name, sizeof(ifreq.ifr_name) - 1);

	fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0) {
		printf("socket failed: %m\n");
		return -1;
	}

	err = ioctl(fd, SIOCGIFHWADDR, &ifreq);
	if (err < 0) {
		printf("ioctl SIOCGIFHWADDR failed: %m\n");
		close(fd);
		return -1;
	}

	close(fd);

	memcpy(slave_mac_addr, &ifreq.ifr_hwaddr.sa_data, MAC_LEN);
	return 0;
}

static int raw_open(const char *hsr_dev, const char *slaveA_dev, const char *slaveB_dev)
{

	if (sk_interface_macaddr(slaveA_dev))
		goto err;

	fd_slaveA = open_socket(slaveA_dev, slave_mac_addr, p2p_dst_mac);
	if (fd_slaveA < 0)
		goto err;

	fd_slaveB = open_socket(slaveB_dev, slave_mac_addr, p2p_dst_mac);
	if (fd_slaveB < 0)
		goto err;

	fd_hsr = open_socket(hsr_dev, slave_mac_addr, p2p_dst_mac);
	if (fd_hsr < 0)
		goto err;

	return 0;

err:
	if (fd_slaveA >= 0)
		close(fd_slaveA);
	if (fd_slaveB >= 0)
		close(fd_slaveB);
	if (fd_hsr >= 0)
		close(fd_hsr);

	return -1;
}

static int sk_receive(int fd, void *buf, int buflen)
{
	struct iovec iov = { buf, buflen };
	uint8_t control[256];
	int32_t cnt = 0;
	struct msghdr msg;

	memset(control, 0, sizeof(control));
	memset(&msg, 0, sizeof(msg));

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	cnt = recvmsg(fd, &msg, MSG_DONTWAIT);
	if (cnt < 0)
		return 0;
	return cnt;
}

static int raw_recv(int fd, void *sample, int sample_len)
{
	struct timespec now, end;
	struct hsr_hdr *hsr_hdr;
	uint8_t buf[1500];
	int32_t cnt;

	/* The packet is expected to arrive within 100ms. HSR will send hello
	 * packets so there an end time and poll() will wait until this point.
	 */
	clock_gettime(CLOCK_MONOTONIC, &now);
	end = now;
	end.tv_nsec += MSEC_TO_NSEC(100);
	tsnorm(&end);
again:

	cnt = sk_receive(fd, buf, sizeof(buf));
	if (cnt == 0) {
		int64_t sleep_time;
		struct pollfd pfd;
		int ret;

		clock_gettime(CLOCK_MONOTONIC, &now);
		if (tsgreater(&now, &end))
			return 0;

		sleep_time = calcdiff(end, now) / 1000;
		if (sleep_time <= 0)
			return 0;

		pfd.fd = fd;
		pfd.events = POLLIN;
		ret = poll(&pfd, 1, sleep_time);
		if (ret <= 0)
			return ret;
		goto again;
	}

	if (cnt < sizeof(struct hsr_hdr))
		goto again;

	hsr_hdr = (void *)buf;
	/* Embedded magic packet passed? */
	if (hsr_hdr->type == htons(ETH_P_1588)) {
		struct hsr_inline_header *hsr_opt = (void *)buf;

		if (hsr_opt->magic == htonl(HSR_INLINE_HDR)) {
			printf("Error: Found HSR_INLINE_HDR\n");
			return -1;
		}
	}
	/* Assuming it is *our* network and nobody but the test here sends
	 * packets to p2p_dst_mac. Therefore any received packet needs to be
	 * ours and every mismatch is considered as error.
	 */
	if (memcmp(hsr_hdr->dst, p2p_dst_mac, MAC_LEN))
		goto again;

	if (hsr_hdr->type != htons(ETH_P_HSR)) {
		printf("Error: Unexpected ether type: 0x%x\n", htons(hsr_hdr->type));
		return -1;
	}

	if (hsr_hdr->encap_type != htons(ETH_P_1588)) {
		printf("Error: Unexpected encapsulated type: 0x%x\n",
		       htons(hsr_hdr->encap_type));
		return -1;
	}

	if (cnt < sizeof(struct hsr_hdr) + sample_len) {
		printf("Error: Packet %d is too small for data check\n", cnt);
		return -1;
	}

	if (!memcmp(&buf[sizeof(struct hsr_hdr)], sample, sample_len))
		return 1;

	printf("Error: Packet did not match the sample\n");
	return -1;
}

static int recv_verify(int port, void *sample, int sample_len)
{
	int32_t error = 0;
	int32_t ret;

	ret = raw_recv(fd_slaveA, sample, sample_len);
	if (ret < 0)
		return ret;
	if (port == PORT_1 && ret == 0) {
		printf("Error: Missing packet on portA\n");
		error = 1;
	}
	if (port == PORT_2 && ret == 1) {
		printf("Error: Not expecting packet on portA\n");
		error = 1;
	}

	ret = raw_recv(fd_slaveB, sample, sample_len);
	if (ret < 0)
		return ret;
	if (port == PORT_2 && ret == 0) {
		printf("Error: Missing packet on portB\n");
		error = 1;
	}
	if (port == PORT_1 && ret == 1) {
		printf("Error: Not expecting packet on portB\n");
		error = 1;
	}
	return error;
}

static int32_t pkt_send(int port, bool hsr_hdr, void *data, int data_len)
{
	struct hsr_meta_header *hdr;
	uint8_t packet[200];
	ssize_t cnt;
	size_t len;

	memset(packet, 0, sizeof(packet));

	len = sizeof(struct hsr_inline_header);
	hdr = (struct hsr_meta_header *)packet;
	memset(&hdr->hsr_opt, 0, sizeof(hdr->hsr_opt));
	hdr->hsr_opt.magic = ntohl(HSR_INLINE_HDR);
	hdr->hsr_opt.eth_type = htons(ETH_P_1588);
	if (port != PORT_1 && port != PORT_2) {
		printf("Wrong port requested\n");
		return -1;
	}
	hdr->hsr_opt.tx_port = port;

	if (hsr_hdr) {
		uint16_t pathid_size;

		len += sizeof(struct hsr_hdr);
		memcpy(&packet[len], data, data_len);

		hdr->hsr_opt.hsr_hdr = 1;

		memcpy(&hdr->hsr_hdr.dst, p2p_dst_mac, MAC_LEN);
		memcpy(&hdr->hsr_hdr.src, slave_mac_addr, MAC_LEN);
		/* Flip a bit in SRC MAC addr so it does not look like hosts */
		hdr->hsr_hdr.src[3] ^= 0x21;

		hdr->hsr_hdr.type = htons(ETH_P_HSR);
		hdr->hsr_hdr.sequence_nr = htons(hsr_seq++);
		hdr->hsr_hdr.encap_type = htons(ETH_P_1588);

		/* The resulting packet must be alteast 66 bytes */
		if (data_len + sizeof(struct hsr_hdr) < 66)
			data_len = 66 - sizeof(struct hsr_hdr);

		pathid_size = data_len + sizeof(struct hsr_hdr) - sizeof(struct eth_hdr);
		pathid_size |= (port - 1) << 12;

		hdr->hsr_hdr.pathid_and_LSDU_size = htons(pathid_size);
	} else {
		len += sizeof(struct eth_hdr);
		hdr->hsr_opt.hsr_hdr = 0;

		memcpy(&hdr->eth_hdr.dst, p2p_dst_mac, MAC_LEN);
		memcpy(&hdr->eth_hdr.src, slave_mac_addr, MAC_LEN);
		hdr->eth_hdr.type = htons(ETH_P_1588);

		memcpy(&packet[len], data, data_len);
	}

	cnt = send(fd_hsr, packet, len + data_len, 0);
	if (cnt < 1)
		return -1;

	return cnt;
}

int main(int argc, char *argv[])
{
	char *slaveA = NULL, *slaveB = NULL, *hsr_dev = NULL;
	char *msg_mode;
	int opt;

	while ((opt = getopt(argc, argv, "A:B:H:")) != -1) {
		switch (opt) {
		case 'A':
			slaveA = strdup(optarg);
			break;

		case 'B':
			slaveB = strdup(optarg);
			break;

		case 'H':
			hsr_dev = strdup(optarg);
			break;
		default: /* '?' */
			fprintf(stderr, "Usage: %s -A slaveA -B slaveB -H hsr_device\n",
				argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	if (!slaveA || !slaveB || !hsr_dev) {
		fprintf(stderr, "Missing network devices\n");
		exit(EXIT_FAILURE);
	}

	if (raw_open(hsr_dev, slaveA, slaveB) < 0)
		return EXIT_FAILURE;

	msg_mode = "PortA, no-hsr-header";
	if (pkt_send(PORT_1, false, ptp_packet, sizeof(ptp_packet)) < 0) {
		printf("Sending failed: %s\n", msg_mode);
		return EXIT_FAILURE;
	}
	if (recv_verify(PORT_1, ptp_packet, sizeof(ptp_packet))) {
		printf("Verify failed: %s\n", msg_mode);
		return EXIT_FAILURE;
	}

	ptp_packet[16 + 4]++;
	msg_mode = "PortB, no-hsr-header";
	if (pkt_send(PORT_2, false, ptp_packet, sizeof(ptp_packet)) < 0) {
		printf("Sending failed: %s\n", msg_mode);
		return EXIT_FAILURE;
	}
	if (recv_verify(PORT_2, ptp_packet, sizeof(ptp_packet))) {
		printf("Sending failed: %s\n", msg_mode);
		return EXIT_FAILURE;
	}

	ptp_packet[16 + 4]++;
	msg_mode = "PortA, hsr-header";
	if (pkt_send(PORT_1, true, ptp_packet, sizeof(ptp_packet)) < 0) {
		printf("Sending failed: %s\n", msg_mode);
		return EXIT_FAILURE;
	}
	if (recv_verify(PORT_1, ptp_packet, sizeof(ptp_packet))) {
		printf("Verify failed: %s\n", msg_mode);
		return EXIT_FAILURE;
	}

	ptp_packet[16 + 4]++;
	msg_mode = "PortB, hsr-header";
	if (pkt_send(PORT_2, true, ptp_packet, sizeof(ptp_packet)) < 0) {
		printf("Sending failed: %s\n", msg_mode);
		return EXIT_FAILURE;
	}
	if (recv_verify(PORT_2, ptp_packet, sizeof(ptp_packet))) {
		printf("Verify failed: %s\n", msg_mode);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
