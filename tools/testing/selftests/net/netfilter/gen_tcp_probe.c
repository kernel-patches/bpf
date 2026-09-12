// SPDX-License-Identifier: GPL-2.0
/*
 * Send a TCP SYN then a TCP ACK (no SYN-ACK, no data) to the VIP.
 * IPVS's TCP state machine only inspects SYN/FIN/ACK/RST bits, so this
 * exercises the INPUT-direction state transition:
 *
 *   SYN:  NONE -> SYN_RECV
 *   ACK:  SYN_RECV -> ESTABLISHED   (tcp_states, normal)
 *         SYN_RECV -> SYN_RECV      (tcp_states_dos, secure_tcp)
 *
 * Requires CAP_NET_RAW.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/if_ether.h>

static inline uint16_t csump(const void *data, size_t len)
{
	const uint16_t *p = data;
	uint32_t sum = 0;

	while (len > 1) {
		sum += *p++;
		len -= 2;
	}
	if (len)
		sum += *(const uint8_t *)p;
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return ~sum;
}

static void send_seg(int fd, const struct in_addr *sip, uint16_t sport,
		     const struct in_addr *dip, uint16_t dport,
		     uint32_t seq, int syn, int ack)
{
	uint8_t pkt[sizeof(struct iphdr) + sizeof(struct tcphdr)] = { 0 };
	struct iphdr *ip = (struct iphdr *)pkt;
	struct tcphdr *tcp = (struct tcphdr *)(pkt + sizeof(struct iphdr));
	struct sockaddr_in dst;

	ip->version = 4;
	ip->ihl = 5;
	ip->tot_len = htons(sizeof(pkt));
	ip->id = htons((uint16_t)(seq & 0xffff));
	ip->ttl = 64;
	ip->protocol = IPPROTO_TCP;
	ip->saddr = sip->s_addr;
	ip->daddr = dip->s_addr;

	tcp->source = sport;
	tcp->dest = dport;
	tcp->seq = htonl(seq);
	tcp->ack_seq = htonl(seq + 1);
	tcp->doff = 5;
	if (syn)
		tcp->syn = 1;
	if (ack)
		tcp->ack = 1;
	tcp->window = htons(1024);

	ip->check = csump(ip, sizeof(struct iphdr));
	/* pseudo header for TCP checksum */
	{
		uint8_t ph[12];

		memcpy(ph, &ip->saddr, 4);
		memcpy(ph + 4, &ip->daddr, 4);
		ph[8] = 0;
		ph[9] = IPPROTO_TCP;
		ph[10] = (sizeof(struct tcphdr) >> 8) & 0xff;
		ph[11] = sizeof(struct tcphdr) & 0xff;

		uint8_t tcpbuf[12 + sizeof(struct tcphdr)];

		memcpy(tcpbuf, ph, 12);
		memcpy(tcpbuf + 12, tcp, sizeof(struct tcphdr));
		tcp->check = csump(tcpbuf, sizeof(tcpbuf));
	}

	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
	dst.sin_addr = *dip;
	dst.sin_port = dport;
	sendto(fd, pkt, sizeof(pkt), 0, (struct sockaddr *)&dst,
	       sizeof(dst));
}

int main(int argc, char *argv[])
{
	struct in_addr sip, dip;
	uint16_t sport, dport;
	int fd, one = 1;
	uint32_t seq = 0x12345678;

	if (argc != 5) {
		fprintf(stderr, "usage: %s <src_ip> <src_port> <dst_ip> <dst_port>\n",
			argv[0]);
		return 2;
	}
	inet_pton(AF_INET, argv[1], &sip);
	sport = htons((uint16_t)atoi(argv[2]));
	inet_pton(AF_INET, argv[3], &dip);
	dport = htons((uint16_t)atoi(argv[4]));

	fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (fd < 0) {
		perror("raw socket");
		return 1;
	}
	setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

	send_seg(fd, &sip, sport, &dip, dport, seq, 1, 0);
	usleep(100000);
	send_seg(fd, &sip, sport, &dip, dport, seq + 1, 0, 1);

	close(fd);
	return 0;
}
