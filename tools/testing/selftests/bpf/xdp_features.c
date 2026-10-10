// SPDX-License-Identifier: GPL-2.0
#include <netinet/in.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/netdev.h>
#include <linux/if_link.h>
#include <argp.h>
#include <errno.h>
#include <net/if.h>
#include <pthread.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <time.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "xdp_features.skel.h"
#include "xdp_features.h"

#define RED(str)	"\033[0;31m" str "\033[0m"
#define GREEN(str)	"\033[0;32m" str "\033[0m"
#define YELLOW(str)	"\033[0;33m" str "\033[0m"

static struct env {
	bool verbosity;
	char ifname[IF_NAMESIZE];
	int ifindex;
	bool is_tester;
	bool query_only;
	struct {
		enum netdev_xdp_act drv_feature;
		enum xdp_action action;
	} feature;
	struct sockaddr_storage dut_ctrl_addr;
	struct sockaddr_storage dut_addr;
	struct sockaddr_storage tester_addr;
} env;

#define BUFSIZE		128

static int make_sockaddr(const char *addr_str, __u16 port,
			 struct sockaddr_storage *addr)
{
	struct sockaddr_in6 *sin6 = (void *)addr;

	memset(addr, 0, sizeof(*addr));
	sin6->sin6_family = AF_INET6;
	sin6->sin6_port = htons(port);
	if (addr_str && inet_pton(AF_INET6, addr_str, &sin6->sin6_addr) != 1)
		return -1;

	return 0;
}

static int settimeo(int fd, int timeout_ms)
{
	struct timeval timeout = { .tv_sec = 3 };

	if (timeout_ms > 0) {
		timeout.tv_sec = timeout_ms / 1000;
		timeout.tv_usec = (timeout_ms % 1000) * 1000;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
		       sizeof(timeout)) ||
	    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout,
		       sizeof(timeout)))
		return -1;

	return 0;
}

static int start_server(int type, __u16 port)
{
	struct sockaddr_storage addr = env.dut_addr;
	int fd, on = 1;

	fd = socket(AF_INET6, type, 0);
	if (fd < 0)
		return -1;

	((struct sockaddr_in6 *)&addr)->sin6_port = htons(port);
	if (settimeo(fd, 0) ||
	    (type == SOCK_STREAM &&
	     setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) ||
	    bind(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in6)) ||
	    (type == SOCK_STREAM && listen(fd, 1))) {
		int err = errno;

		close(fd);
		errno = err;
		return -1;
	}

	return fd;
}

static int libbpf_print_fn(enum libbpf_print_level level,
			   const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbosity)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile sig_atomic_t stop_signal;
static atomic_bool exiting;

static bool should_exit(void)
{
	return stop_signal || atomic_load(&exiting);
}

static void sig_handler(int sig)
{
	stop_signal = sig;
}

const char *argp_program_version = "xdp-features 0.0";
const char argp_program_doc[] =
"XDP features detection application.\n"
"\n"
"XDP features application checks the XDP advertised features match detected ones.\n"
"\n"
"USAGE: ./xdp-features [-vt] [-f <xdp-feature>] [-D <dut-data-ip>] [-T <tester-data-ip>] [-C <dut-ctrl-ip>] <iface-name>\n"
"\n"
"dut-data-ip, tester-data-ip, dut-ctrl-ip: IPv6 or IPv4-mapped-IPv6 addresses;\n"
"\n"
"XDP features\n:"
"- XDP_PASS\n"
"- XDP_DROP\n"
"- XDP_ABORTED\n"
"- XDP_REDIRECT\n"
"- XDP_NDO_XMIT\n"
"- XDP_TX\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "tester", 't', NULL, 0, "Tester mode" },
	{ "query", 'q', NULL, 0, "Check native XDP support without attaching" },
	{ "feature", 'f', "XDP-FEATURE", 0, "XDP feature to test" },
	{ "dut_data_ip", 'D', "DUT-DATA-IP", 0, "DUT IP data channel" },
	{ "dut_ctrl_ip", 'C', "DUT-CTRL-IP", 0, "DUT IP control channel" },
	{ "tester_data_ip", 'T', "TESTER-DATA-IP", 0, "Tester IP data channel" },
	{},
};

static int get_xdp_feature(const char *arg)
{
	if (!strcmp(arg, "XDP_PASS")) {
		env.feature.action = XDP_PASS;
		env.feature.drv_feature = NETDEV_XDP_ACT_BASIC;
	} else if (!strcmp(arg, "XDP_DROP")) {
		env.feature.drv_feature = NETDEV_XDP_ACT_BASIC;
		env.feature.action = XDP_DROP;
	} else if (!strcmp(arg, "XDP_ABORTED")) {
		env.feature.drv_feature = NETDEV_XDP_ACT_BASIC;
		env.feature.action = XDP_ABORTED;
	} else if (!strcmp(arg, "XDP_TX")) {
		env.feature.drv_feature = NETDEV_XDP_ACT_BASIC;
		env.feature.action = XDP_TX;
	} else if (!strcmp(arg, "XDP_REDIRECT")) {
		env.feature.drv_feature = NETDEV_XDP_ACT_REDIRECT;
		env.feature.action = XDP_REDIRECT;
	} else if (!strcmp(arg, "XDP_NDO_XMIT")) {
		env.feature.drv_feature = NETDEV_XDP_ACT_NDO_XMIT;
	} else {
		return -EINVAL;
	}

	return 0;
}

static char *get_xdp_feature_str(void)
{
	switch (env.feature.action) {
	case XDP_PASS:
		return YELLOW("XDP_PASS");
	case XDP_DROP:
		return YELLOW("XDP_DROP");
	case XDP_ABORTED:
		return YELLOW("XDP_ABORTED");
	case XDP_TX:
		return YELLOW("XDP_TX");
	case XDP_REDIRECT:
		return YELLOW("XDP_REDIRECT");
	default:
		break;
	}

	if (env.feature.drv_feature == NETDEV_XDP_ACT_NDO_XMIT)
		return YELLOW("XDP_NDO_XMIT");

	return "";
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbosity = true;
		break;
	case 'q':
		env.query_only = true;
		break;
	case 't':
		env.is_tester = true;
		break;
	case 'f':
		if (get_xdp_feature(arg) < 0) {
			fprintf(stderr, "Invalid xdp feature: %s\n", arg);
			argp_usage(state);
			return ARGP_ERR_UNKNOWN;
		}
		break;
	case 'D':
		if (make_sockaddr(arg, DUT_ECHO_PORT, &env.dut_addr)) {
			fprintf(stderr,
				"Invalid address assigned to the Device Under Test: %s\n",
				arg);
			return ARGP_ERR_UNKNOWN;
		}
		break;
	case 'C':
		if (make_sockaddr(arg, DUT_CTRL_PORT, &env.dut_ctrl_addr)) {
			fprintf(stderr,
				"Invalid address assigned to the Device Under Test: %s\n",
				arg);
			return ARGP_ERR_UNKNOWN;
		}
		break;
	case 'T':
		if (make_sockaddr(arg, 0, &env.tester_addr)) {
			fprintf(stderr,
				"Invalid address assigned to the Tester device: %s\n",
				arg);
			return ARGP_ERR_UNKNOWN;
		}
		break;
	case ARGP_KEY_ARG:
		errno = 0;
		if (strlen(arg) >= IF_NAMESIZE) {
			fprintf(stderr, "Invalid device name: %s\n", arg);
			argp_usage(state);
			return ARGP_ERR_UNKNOWN;
		}

		env.ifindex = if_nametoindex(arg);
		if (!env.ifindex)
			env.ifindex = strtoul(arg, NULL, 0);
		if (!env.ifindex || !if_indextoname(env.ifindex, env.ifname)) {
			fprintf(stderr,
				"Bad interface index or name (%d): %s\n",
				errno, strerror(errno));
			argp_usage(state);
			return ARGP_ERR_UNKNOWN;
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

static void set_env_default(void)
{
	env.feature.drv_feature = NETDEV_XDP_ACT_NDO_XMIT;
	env.feature.action = -EINVAL;
	env.ifindex = -ENODEV;
	snprintf(env.ifname, sizeof(env.ifname), "unknown");
	make_sockaddr("::ffff:127.0.0.1", DUT_CTRL_PORT,
		      &env.dut_ctrl_addr);
	make_sockaddr("::ffff:127.0.0.1", DUT_ECHO_PORT, &env.dut_addr);
	make_sockaddr("::ffff:127.0.0.1", 0, &env.tester_addr);
}

static void *dut_echo_thread(void *arg)
{
	unsigned char buf[sizeof(struct tlv_hdr)];
	int sockfd = *(int *)arg;

	while (!should_exit()) {
		struct tlv_hdr *tlv = (struct tlv_hdr *)buf;
		struct sockaddr_storage addr;
		socklen_t addrlen = sizeof(addr);
		ssize_t n;

		n = recvfrom(sockfd, buf, sizeof(buf), MSG_WAITALL,
			     (struct sockaddr *)&addr, &addrlen);
		if (n != sizeof(*tlv) || n != ntohs(tlv->len))
			continue;

		if (ntohs(tlv->type) != CMD_ECHO)
			continue;

		sendto(sockfd, buf, sizeof(buf), MSG_NOSIGNAL | MSG_CONFIRM,
		       (struct sockaddr *)&addr, addrlen);
	}

	close(sockfd);

	return NULL;
}

static int dut_run_echo_thread(pthread_t *t, int *sockfd)
{
	int err;

	*sockfd = start_server(SOCK_DGRAM, DUT_ECHO_PORT);
	if (*sockfd < 0) {
		fprintf(stderr,
			"Failed creating data UDP socket on device %s\n",
			env.ifname);
		return -errno;
	}

	/* start echo channel */
	err = pthread_create(t, NULL, dut_echo_thread, sockfd);
	if (err) {
		fprintf(stderr,
			"Failed creating data UDP thread on device %s: %s\n",
			env.ifname, strerror(err));
		close(*sockfd);
		return -EINVAL;
	}

	return 0;
}

static int dut_attach_xdp_prog(struct xdp_features *skel)
{
	enum xdp_action action = env.feature.action;
	struct bpf_program *prog;
	unsigned int key = 0;
	int err, fd = 0;
	LIBBPF_OPTS(bpf_link_create_opts, opts, .flags = XDP_FLAGS_DRV_MODE);

	if (env.feature.drv_feature == NETDEV_XDP_ACT_NDO_XMIT) {
		struct bpf_devmap_val entry = {
			.ifindex = env.ifindex,
		};

		err = bpf_map__update_elem(skel->maps.dev_map,
					   &key, sizeof(key),
					   &entry, sizeof(entry), 0);
		if (err < 0)
			return err;

		fd = bpf_program__fd(skel->progs.xdp_do_redirect_cpumap);
		action = XDP_REDIRECT;
	}

	switch (action) {
	case XDP_TX:
		prog = skel->progs.xdp_do_tx;
		break;
	case XDP_DROP:
		prog = skel->progs.xdp_do_drop;
		break;
	case XDP_ABORTED:
		prog = skel->progs.xdp_do_aborted;
		break;
	case XDP_PASS:
		prog = skel->progs.xdp_do_pass;
		break;
	case XDP_REDIRECT: {
		struct bpf_cpumap_val entry = {
			.qsize = 2048,
			.bpf_prog.fd = fd,
		};

		err = bpf_map__update_elem(skel->maps.cpu_map,
					   &key, sizeof(key),
					   &entry, sizeof(entry), 0);
		if (err < 0)
			return err;

		prog = skel->progs.xdp_do_redirect;
		break;
	}
	default:
		return -EINVAL;
	}

	err = bpf_link_create(bpf_program__fd(prog), env.ifindex, BPF_XDP,
			      &opts);
	if (err < 0)
		fprintf(stderr, "Failed attaching XDP program to device %s\n",
			env.ifname);
	return err;
}

static int send_msg(int sockfd, const void *buf, size_t len)
{
	const char *data = buf;

	while (len && !should_exit()) {
		ssize_t n = send(sockfd, data, len, MSG_NOSIGNAL);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (!n)
			return -EIO;
		data += n;
		len -= n;
	}
	return len ? -EINTR : 0;
}

static int recv_msg(int sockfd, void *buf, size_t bufsize, void *val,
		    size_t val_size)
{
	struct tlv_hdr *tlv = (struct tlv_hdr *)buf;
	ssize_t received;
	size_t len;

	received = recv(sockfd, buf, sizeof(*tlv), MSG_WAITALL);
	if (received < 0)
		return -errno;
	if (received != sizeof(*tlv))
		return -ECONNRESET;
	len = ntohs(tlv->len);
	if (len < sizeof(*tlv) || len > bufsize)
		return -EINVAL;
	if (len > sizeof(*tlv)) {
		received = recv(sockfd, tlv->data, len - sizeof(*tlv), MSG_WAITALL);
		if (received < 0 || (size_t)received != len - sizeof(*tlv))
			return -ECONNRESET;
	}

	if (val) {
		len -= sizeof(*tlv);
		if (len != val_size)
			return -ENOMEM;

		memcpy(val, tlv->data, len);
	}

	return 0;
}

static int dut_run(struct xdp_features *skel)
{
	int link_fd = -1;
	int state = CMD_STOP, err = 0, sockfd, ctrl_sockfd, echo_sockfd;
	struct sockaddr_storage ctrl_addr;
	pthread_t dut_thread;
	bool thread_started = false;
	int attempt;
	socklen_t addrlen = sizeof(ctrl_addr);

	sockfd = start_server(SOCK_STREAM, DUT_CTRL_PORT);
	if (sockfd < 0) {
		fprintf(stderr,
			"Failed creating control socket on device %s\n", env.ifname);
		return -errno;
	}

	/* Allow remote startup and BPF loading on slow test machines. */
	ctrl_sockfd = -1;
	for (attempt = 0; attempt < 20 && !should_exit(); attempt++) {
		addrlen = sizeof(ctrl_addr);
		ctrl_sockfd = accept(sockfd, (struct sockaddr *)&ctrl_addr,
				     &addrlen);
		if (ctrl_sockfd >= 0 || (errno != EAGAIN && errno != EINTR))
			break;
	}
	if (ctrl_sockfd < 0) {
		fprintf(stderr,
			"Failed accepting connections on device %s control socket\n",
			env.ifname);
		err = should_exit() ? -EINTR : -errno;
		close(sockfd);
		return err;
	}

	if (memcmp(&((struct sockaddr_in6 *)&ctrl_addr)->sin6_addr,
		   &((struct sockaddr_in6 *)&env.tester_addr)->sin6_addr,
		   sizeof(struct in6_addr))) {
		err = -EPERM;
		goto out;
	}

	if (settimeo(ctrl_sockfd, 3000)) {
		err = -errno;
		goto out;
	}

	/* CTRL loop */
	while (!should_exit()) {
		unsigned char buf[BUFSIZE] = {};
		struct tlv_hdr *tlv = (struct tlv_hdr *)buf;

		err = recv_msg(ctrl_sockfd, buf, BUFSIZE, NULL, 0);
		if (err == -EAGAIN || err == -EINTR)
			continue;
		if (err)
			goto end_thread;

		switch (ntohs(tlv->type)) {
		case CMD_START: {
			if (state == CMD_START)
				continue;

			state = CMD_START;
			/* Load the XDP program on the DUT */
			link_fd = dut_attach_xdp_prog(skel);
			if (link_fd < 0) {
				err = link_fd;
				goto out;
			}

			err = dut_run_echo_thread(&dut_thread, &echo_sockfd);
			if (err < 0)
				goto out;
			thread_started = true;

			tlv->type = htons(CMD_ACK);
			tlv->len = htons(sizeof(*tlv));
			err = send_msg(ctrl_sockfd, buf, sizeof(*tlv));
			if (err < 0)
				goto end_thread;
			break;
		}
		case CMD_STOP:
			if (state != CMD_START)
				break;

			state = CMD_STOP;

			tlv->type = htons(CMD_ACK);
			tlv->len = htons(sizeof(*tlv));
			err = send_msg(ctrl_sockfd, buf, sizeof(*tlv));
			goto end_thread;
		case CMD_GET_MAC: {
			struct ifreq ifr = {};

			snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", env.ifname);
			if (ioctl(sockfd, SIOCGIFHWADDR, &ifr)) {
				err = -errno;
				goto end_thread;
			}
			tlv->type = htons(CMD_ACK);
			tlv->len = htons(sizeof(*tlv) + ETH_ALEN);
			memcpy(tlv->data, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
			err = send_msg(ctrl_sockfd, buf, sizeof(*tlv) + ETH_ALEN);
			if (err)
				goto end_thread;
			break;
		}
		case CMD_GET_XDP_CAP: {
			LIBBPF_OPTS(bpf_xdp_query_opts, opts);
			unsigned long long val;
			size_t n;

			err = bpf_xdp_query(env.ifindex, XDP_FLAGS_DRV_MODE,
					    &opts);
			if (err) {
				fprintf(stderr,
					"Failed querying XDP cap for device %s\n",
					env.ifname);
				goto end_thread;
			}

			tlv->type = htons(CMD_ACK);
			n = sizeof(*tlv) + sizeof(opts.feature_flags);
			tlv->len = htons(n);

			val = htobe64(opts.feature_flags);
			memcpy(tlv->data, &val, sizeof(val));

			err = send_msg(ctrl_sockfd, buf, n);
			if (err < 0)
				goto end_thread;
			break;
		}
		case CMD_GET_STATS: {
			unsigned int key = 0, val;
			size_t n;

			err = bpf_map__lookup_elem(skel->maps.dut_stats,
						   &key, sizeof(key),
						   &val, sizeof(val), 0);
			if (err) {
				fprintf(stderr,
					"bpf_map_lookup_elem failed (%d)\n", err);
				goto end_thread;
			}

			tlv->type = htons(CMD_ACK);
			n = sizeof(*tlv) + sizeof(val);
			tlv->len = htons(n);

			val = htonl(val);
			memcpy(tlv->data, &val, sizeof(val));

			err = send_msg(ctrl_sockfd, buf, n);
			if (err < 0)
				goto end_thread;
			break;
		}
		default:
			break;
		}
	}

end_thread:
	exiting = true;
	if (thread_started)
		pthread_join(dut_thread, NULL);
out:
	if (link_fd >= 0)
		close(link_fd);
	close(ctrl_sockfd);
	close(sockfd);

	return err;
}

static int send_and_recv_msg(int sockfd, enum test_commands cmd, void *val,
			     size_t val_size)
{
	unsigned char buf[BUFSIZE] = {};
	struct tlv_hdr *tlv = (struct tlv_hdr *)buf;
	int err;

	tlv->type = htons(cmd);
	tlv->len = htons(sizeof(*tlv));

	err = send_msg(sockfd, buf, sizeof(*tlv));
	if (err < 0)
		return err;

	err = recv_msg(sockfd, buf, BUFSIZE, val, val_size);
	if (err < 0)
		return err;

	return ntohs(tlv->type) == CMD_ACK ? 0 : -EINVAL;
}

/* Compute checksums in software; packet sockets do not request TX offload. */
static __u16 packet_checksum(const void *data, size_t len)
{
	const unsigned char *p = data;
	unsigned int sum = 0;

	while (len > 1) {
		sum += (p[0] << 8) | p[1];
		p += 2;
		len -= 2;
	}
	if (len)
		sum += p[0] << 8;
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return ~sum;
}

static size_t make_echo_packet(unsigned char *packet, __be16 source_port)
{
	const struct in6_addr *src = &((struct sockaddr_in6 *)&env.tester_addr)->sin6_addr;
	const struct in6_addr *dst = &((struct sockaddr_in6 *)&env.dut_addr)->sin6_addr;
	struct udphdr udp = {
		.source = source_port,
		.dest = htons(DUT_ECHO_PORT),
		.len = htons(sizeof(udp) + sizeof(struct tlv_hdr)),
	};
	struct tlv_hdr echo = {
		.type = htons(CMD_ECHO),
		.len = htons(sizeof(echo)),
	};
	unsigned char pseudo[40 + sizeof(udp) + sizeof(echo)] = {};
	size_t ip_len, pseudo_len;
	__u16 checksum;

	if (IN6_IS_ADDR_V4MAPPED(dst)) {
		struct iphdr ip = {
			.version = 4, .ihl = 5, .ttl = 64,
			.protocol = IPPROTO_UDP,
			.tot_len = htons(sizeof(ip) + sizeof(udp) + sizeof(echo)),
		};

		memcpy(&ip.saddr, &src->s6_addr[12], 4);
		memcpy(&ip.daddr, &dst->s6_addr[12], 4);
		ip.check = htons(packet_checksum(&ip, sizeof(ip)));
		memcpy(packet, &ip, sizeof(ip));
		memcpy(pseudo, &ip.saddr, 4);
		memcpy(pseudo + 4, &ip.daddr, 4);
		pseudo[9] = IPPROTO_UDP;
		memcpy(pseudo + 10, &udp.len, 2);
		pseudo_len = 12;
		ip_len = sizeof(ip);
	} else {
		struct ipv6hdr ip = {
			.version = 6, .hop_limit = 64,
			.nexthdr = IPPROTO_UDP, .payload_len = udp.len,
			.saddr = *src, .daddr = *dst,
		};
		__be32 len = htonl(sizeof(udp) + sizeof(echo));

		memcpy(packet, &ip, sizeof(ip));
		memcpy(pseudo, src, sizeof(*src));
		memcpy(pseudo + 16, dst, sizeof(*dst));
		memcpy(pseudo + 32, &len, sizeof(len));
		pseudo[39] = IPPROTO_UDP;
		pseudo_len = 40;
		ip_len = sizeof(ip);
	}
	memcpy(pseudo + pseudo_len, &udp, sizeof(udp));
	memcpy(pseudo + pseudo_len + sizeof(udp), &echo, sizeof(echo));
	checksum = packet_checksum(pseudo, pseudo_len + sizeof(udp) + sizeof(echo));
	udp.check = htons(checksum ? checksum : 0xffff);
	memcpy(packet + ip_len, &udp, sizeof(udp));
	memcpy(packet + ip_len + sizeof(udp), &echo, sizeof(echo));
	return ip_len + sizeof(udp) + sizeof(echo);
}

static bool is_echo_reply(const unsigned char *packet, size_t len,
			  __be16 source_port)
{
	const struct in6_addr *tester = &((struct sockaddr_in6 *)&env.tester_addr)->sin6_addr;
	const struct in6_addr *dut = &((struct sockaddr_in6 *)&env.dut_addr)->sin6_addr;
	bool reflected = env.feature.action == XDP_TX ||
			 env.feature.drv_feature == NETDEV_XDP_ACT_NDO_XMIT;
	const struct in6_addr *src = reflected ? tester : dut;
	const struct in6_addr *dst = reflected ? dut : tester;
	struct tlv_hdr echo;
	struct udphdr udp;
	size_t ip_len;

	if (IN6_IS_ADDR_V4MAPPED(dut)) {
		struct iphdr ip;

		if (len < sizeof(ip))
			return false;
		memcpy(&ip, packet, sizeof(ip));
		ip_len = ip.ihl * 4;
		if (ip.version != 4 || ip_len < sizeof(ip) ||
		    ip.protocol != IPPROTO_UDP ||
		    memcmp(&ip.saddr, &src->s6_addr[12], 4) ||
		    memcmp(&ip.daddr, &dst->s6_addr[12], 4))
			return false;
	} else {
		struct ipv6hdr ip;

		if (len < sizeof(ip))
			return false;
		memcpy(&ip, packet, sizeof(ip));
		ip_len = sizeof(ip);
		if (ip.version != 6 || ip.nexthdr != IPPROTO_UDP ||
		    memcmp(&ip.saddr, src, sizeof(*src)) ||
		    memcmp(&ip.daddr, dst, sizeof(*dst)))
			return false;
	}
	if (len < ip_len + sizeof(udp) + sizeof(echo))
		return false;
	memcpy(&udp, packet + ip_len, sizeof(udp));
	memcpy(&echo, packet + ip_len + sizeof(udp), sizeof(echo));
	return udp.source == (reflected ? source_port : htons(DUT_ECHO_PORT)) &&
	       udp.dest == (reflected ? htons(DUT_ECHO_PORT) : source_port) &&
	       echo.type == htons(CMD_ECHO) && echo.len == htons(sizeof(echo));
}

static long long monotonic_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int collect_echoes(int fd, __be16 source_port, unsigned int *count)
{
	long long deadline = monotonic_ms() + 1000;
	struct pollfd pfd = { .fd = fd, .events = POLLIN };

	while (!should_exit()) {
		unsigned char packet[2048];
		struct sockaddr_ll from;
		socklen_t addrlen = sizeof(from);
		int remaining = deadline - monotonic_ms();
		ssize_t len;
		int err;

		if (remaining <= 0)
			break;
		err = poll(&pfd, 1, remaining);
		if (err < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (!err)
			break;
		len = recvfrom(fd, packet, sizeof(packet), MSG_DONTWAIT,
			       (struct sockaddr *)&from, &addrlen);
		if (len < 0) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			return -errno;
		}
		if (env.verbosity)
			fprintf(stderr, "packet type=%u len=%zd match=%d\n",
				from.sll_pkttype, len,
				is_echo_reply(packet, len, source_port));
		if (from.sll_pkttype != PACKET_OUTGOING &&
		    is_echo_reply(packet, len, source_port))
			(*count)++;
	}
	return should_exit() ? -EINTR : 0;
}

static int tester_run(void)
{
	struct sockaddr_ll peer = {
		.sll_family = AF_PACKET, .sll_ifindex = env.ifindex,
		.sll_protocol = htons(ETH_P_ALL), .sll_halen = ETH_ALEN,
	};
	struct sockaddr_in6 local = *(struct sockaddr_in6 *)&env.tester_addr;
	unsigned long long advertised_feature;
	unsigned int stats, received = 0;
	unsigned char packet[128];
	int data_fd = -1, port_fd = -1;
	socklen_t addrlen = sizeof(local);
	int i, err, sockfd;
	size_t packet_len;
	bool detected_cap;

	sockfd = socket(AF_INET6, SOCK_STREAM, 0);
	if (sockfd < 0)
		return -errno;
	if (settimeo(sockfd, 30000) ||
	    bind(sockfd, (struct sockaddr *)&local, sizeof(local)) ||
	    connect(sockfd, (struct sockaddr *)&env.dut_ctrl_addr,
		    sizeof(struct sockaddr_in6))) {
		err = -errno;
		goto out;
	}
	err = send_and_recv_msg(sockfd, CMD_GET_XDP_CAP, &advertised_feature,
				sizeof(advertised_feature));
	if (err)
		goto out;
	advertised_feature = be64toh(advertised_feature);
	err = send_and_recv_msg(sockfd, CMD_GET_MAC, peer.sll_addr, ETH_ALEN);
	if (err)
		goto out;

	/* Reserve an ephemeral source port without changing the peer NIC. */
	port_fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (port_fd < 0 || bind(port_fd, (struct sockaddr *)&local, sizeof(local)) ||
	    getsockname(port_fd, (struct sockaddr *)&local, &addrlen)) {
		err = -errno;
		goto out;
	}
	data_fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
	if (data_fd < 0 || bind(data_fd, (struct sockaddr *)&peer, sizeof(peer))) {
		err = -errno;
		goto out;
	}
	peer.sll_protocol = IN6_IS_ADDR_V4MAPPED(&local.sin6_addr) ?
			    htons(ETH_P_IP) : htons(ETH_P_IPV6);
	packet_len = make_echo_packet(packet, local.sin6_port);
	err = send_and_recv_msg(sockfd, CMD_START, NULL, 0);
	if (err)
		goto out;
	for (i = 0; i < 10 && !should_exit(); i++) {
		ssize_t len;

		len = sendto(data_fd, packet, packet_len, 0,
			     (struct sockaddr *)&peer, sizeof(peer));
		if (len < 0 || (size_t)len != packet_len) {
			err = len < 0 ? -errno : -EIO;
			goto out;
		}
		err = collect_echoes(data_fd, local.sin6_port, &received);
		if (err)
			goto out;
	}
	err = send_and_recv_msg(sockfd, CMD_GET_STATS, &stats, sizeof(stats));
	if (err)
		goto out;
	detected_cap = ntohl(stats) &&
		       ((env.feature.action == XDP_DROP ||
			 env.feature.action == XDP_ABORTED) ? !received : received);
	if (env.verbosity)
		fprintf(stderr, "dut=%u received=%u advertised=%llx\n",
			ntohl(stats), received, advertised_feature);
	err = send_and_recv_msg(sockfd, CMD_STOP, NULL, 0);
	if (err)
		goto out;
	fprintf(stdout, "Feature %s: [%s][%s]\n", get_xdp_feature_str(),
		detected_cap ? GREEN("DETECTED") : RED("NOT DETECTED"),
		env.feature.drv_feature & advertised_feature ? GREEN("ADVERTISED")
							     : RED("NOT ADVERTISED"));
out:
	if (data_fd >= 0)
		close(data_fd);
	if (port_fd >= 0)
		close(port_fd);
	close(sockfd);
	return err;
}

int main(int argc, char **argv)
{
	struct xdp_features *skel;
	int err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_print_fn);

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	signal(SIGALRM, sig_handler);
	alarm(90);

	set_env_default();

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (env.ifindex < 0) {
		fprintf(stderr, "Invalid device name %s\n", env.ifname);
		return -ENODEV;
	}

	if (env.query_only) {
		LIBBPF_OPTS(bpf_xdp_query_opts, opts);

		err = bpf_xdp_query(env.ifindex, XDP_FLAGS_DRV_MODE, &opts);
		if (err)
			return 1;
		return opts.feature_flags & NETDEV_XDP_ACT_BASIC ? 0 : 4;
	}

	if (env.is_tester) {
		err = tester_run();
		return stop_signal ? EINTR : (err < 0 ? -err : 0);
	}

	/* Load and verify BPF application */
	skel = xdp_features__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return -EINVAL;
	}

	skel->rodata->tester_addr =
		((struct sockaddr_in6 *)&env.tester_addr)->sin6_addr;
	skel->rodata->dut_addr =
		((struct sockaddr_in6 *)&env.dut_addr)->sin6_addr;

	/* Load & verify BPF programs */
	err = xdp_features__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	err = xdp_features__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	err = dut_run(skel);

cleanup:
	xdp_features__destroy(skel);

	if (stop_signal)
		return EINTR;
	return err < 0 ? -err : 0;
}
