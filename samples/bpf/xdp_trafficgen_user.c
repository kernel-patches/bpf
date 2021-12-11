// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2021 Toke Høiland-Jørgensen <toke@redhat.com>
 */
static const char *__doc__ =
"XDP trafficgen tool, using bpf_redirect helper\n"
"Usage: xdp_trafficgen [options] <IFINDEX|IFNAME>_OUT\n";

#define _GNU_SOURCE
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/in6.h>
#include <linux/udp.h>
#include <assert.h>
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <net/if.h>
#include <unistd.h>
#include <libgen.h>
#include <limits.h>
#include <getopt.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <bpf/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/libbpf.h>
#include "bpf_util.h"
#include "xdp_sample_user.h"
#include "xdp_redirect.skel.h"

static int mask = SAMPLE_REDIRECT_ERR_CNT |
		  SAMPLE_EXCEPTION_CNT | SAMPLE_DEVMAP_XMIT_CNT_MULTI;

DEFINE_SAMPLE_INIT(xdp_redirect);

static const struct option long_options[] = {
	{"dst-mac",	required_argument,	NULL, 'm' },
	{"src-mac",	required_argument,	NULL, 'M' },
	{"dst-ip",	required_argument,	NULL, 'a' },
	{"src-ip",	required_argument,	NULL, 'A' },
	{"dst-port",	required_argument,	NULL, 'p' },
	{"src-port",	required_argument,	NULL, 'P' },
	{"dynamic-ports", required_argument,	NULL, 'd' },
	{"help",	no_argument,		NULL, 'h' },
	{"stats",	no_argument,		NULL, 's' },
	{"interval",	required_argument,	NULL, 'i' },
	{"n-pkts",	required_argument,	NULL, 'n' },
	{"threads",	required_argument,	NULL, 't' },
	{"verbose",	no_argument,		NULL, 'v' },
	{}
};

static int sample_res;
static bool sample_exited;

static void *run_samples(void *arg)
{
	unsigned long *interval = arg;

	sample_res = sample_run(*interval, NULL, NULL);
	sample_exited = true;
	return NULL;
}

struct ipv6_packet {
	struct ethhdr eth;
	struct ipv6hdr iph;
	struct udphdr udp;
	__u8 payload[64 - sizeof(struct udphdr)
		     - sizeof(struct ethhdr) - sizeof(struct ipv6hdr)];
} __packed;
static struct ipv6_packet pkt_v6 = {
	.eth.h_proto = __bpf_constant_htons(ETH_P_IPV6),
	.iph.version = 6,
	.iph.nexthdr = IPPROTO_UDP,
	.iph.payload_len = bpf_htons(sizeof(struct ipv6_packet)
				     - offsetof(struct ipv6_packet, udp)),
	.iph.hop_limit = 1,
	.iph.saddr.s6_addr16 = {bpf_htons(0xfe80), 0, 0, 0, 0, 0, 0, bpf_htons(1)},
	.iph.daddr.s6_addr16 = {bpf_htons(0xfe80), 0, 0, 0, 0, 0, 0, bpf_htons(2)},
	.udp.source = bpf_htons(1),
	.udp.dest = bpf_htons(1),
	.udp.len = bpf_htons(sizeof(struct ipv6_packet)
			     - offsetof(struct ipv6_packet, udp)),
};

struct thread_config {
	void *pkt;
	size_t pkt_size;
	__u32 cpu_core_id;
	__u32 num_pkts;
	int prog_fd;
};

struct config {
	__be64 src_mac;
	__be64 dst_mac;
	struct in6_addr src_ip;
	struct in6_addr dst_ip;
	__be16 src_port;
	__be16 dst_port;
	int ifindex;
	char ifname[IFNAMSIZ];
};

static void *run_traffic(void *arg)
{
	const struct thread_config *cfg = arg;
	struct xdp_md ctx_in = {
		.data_end = cfg->pkt_size,
	};
	DECLARE_LIBBPF_OPTS(bpf_test_run_opts, opts,
			    .data_in = cfg->pkt,
			    .data_size_in = cfg->pkt_size,
			    .ctx_in = &ctx_in,
			    .ctx_size_in = sizeof(ctx_in),
			    .repeat = cfg->num_pkts ?: 1 << 24,
			    .flags = BPF_F_TEST_XDP_DO_REDIRECT,
		);
	__u64 iterations = 0;
	cpu_set_t cpu_cores;
	int err;

	CPU_ZERO(&cpu_cores);
	CPU_SET(cfg->cpu_core_id, &cpu_cores);
	pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpu_cores);
	do {
		err = bpf_prog_test_run_opts(cfg->prog_fd, &opts);
		if (err) {
			printf("bpf_prog_test_run ret %d errno %d\n", err, errno);
			break;
		}
		iterations += opts.repeat;
	} while (!sample_exited && (!cfg->num_pkts || cfg->num_pkts < iterations));
	return NULL;
}

static __be16 calc_udp_cksum(const struct ipv6_packet *pkt)
{
	__u32 chksum = pkt->iph.nexthdr + bpf_ntohs(pkt->iph.payload_len);
	int i;

	for (i = 0; i < 8; i++) {
		chksum += bpf_ntohs(pkt->iph.saddr.s6_addr16[i]);
		chksum += bpf_ntohs(pkt->iph.daddr.s6_addr16[i]);
	}
	chksum += bpf_ntohs(pkt->udp.source);
	chksum += bpf_ntohs(pkt->udp.dest);
	chksum += bpf_ntohs(pkt->udp.len);

	while (chksum >> 16)
		chksum = (chksum & 0xFFFF) + (chksum >> 16);
	return bpf_htons(~chksum);
}

static int prepare_pkt(struct config *cfg)
{
	__be64 src_mac = cfg->src_mac;
	struct in6_addr nulladdr = {};
	int i, err;

	if (!src_mac) {
		err = get_mac_addr(cfg->ifindex, &src_mac);
		if (err)
			return err;
	}
	for (i = 0; i < 6 ; i++) {
		pkt_v6.eth.h_source[i] = *((__u8 *)&src_mac + i);
		if (cfg->dst_mac)
			pkt_v6.eth.h_dest[i] = *((__u8 *)&cfg->dst_mac + i);
	}
	if (memcmp(&cfg->src_ip, &nulladdr, sizeof(nulladdr)))
		pkt_v6.iph.saddr = cfg->src_ip;
	if (memcmp(&cfg->dst_ip, &nulladdr, sizeof(nulladdr)))
		pkt_v6.iph.daddr = cfg->dst_ip;
	if (cfg->src_port)
		pkt_v6.udp.source = cfg->src_port;
	if (cfg->dst_port)
		pkt_v6.udp.dest = cfg->dst_port;
	pkt_v6.udp.check = calc_udp_cksum(&pkt_v6);
	return 0;
}

int main(int argc, char **argv)
{
	unsigned long interval = 2, threads = 1, dynports = 0;
	__u64 num_pkts = 0;
	pthread_t sample_thread, *runner_threads = NULL;
	struct thread_config *t = NULL, tcfg = {
		.pkt = &pkt_v6,
		.pkt_size = sizeof(pkt_v6),
	};
	int ret = EXIT_FAIL_OPTION;
	struct xdp_redirect *skel;
	struct config cfg = {};
	bool error = true;
	int opt, i, err;

	while ((opt = getopt_long(argc, argv, "a:A:d:hi:m:M:n:p:P:t:vs",
				  long_options, NULL)) != -1) {
		switch (opt) {
		case 'a':
			if (!inet_pton(AF_INET6, optarg, &cfg.dst_ip)) {
				fprintf(stderr, "Invalid IPv6 address: %s\n", optarg);
				return -1;
			}
			break;
		case 'A':
			if (!inet_pton(AF_INET6, optarg, &cfg.src_ip)) {
				fprintf(stderr, "Invalid IPv6 address: %s\n", optarg);
				return -1;
			}
			break;
		case 'd':
			dynports = strtoul(optarg, NULL, 0);
			if (dynports < 2 || dynports >= 65535) {
				fprintf(stderr, "Dynamic port range must be >1 and < 65535\n");
				return -1;
			}
			break;
		case 'i':
			interval = strtoul(optarg, NULL, 0);
			if (interval < 1 || interval == ULONG_MAX) {
				fprintf(stderr, "Need non-zero interval\n");
				return -1;
			}
			break;
		case 't':
			threads = strtoul(optarg, NULL, 0);
			if (threads < 1 || threads == ULONG_MAX) {
				fprintf(stderr, "Need at least 1 thread\n");
				return -1;
			}
			break;
		case 'm':
		case 'M':
			struct ether_addr *a;

			a = ether_aton(optarg);
			if (!a) {
				fprintf(stderr, "Invalid MAC: %s\n", optarg);
				return -1;
			}
			if (opt == 'm')
				memcpy(&cfg.dst_mac, a, sizeof(*a));
			else
				memcpy(&cfg.src_mac, a, sizeof(*a));
			break;
		case 'n':
			num_pkts = strtoull(optarg, NULL, 0);
			if (num_pkts >= 1ULL << 32) {
				fprintf(stderr, "Can send up to 2^32-1 pkts or infinite (0)\n");
				return -1;
			}
			tcfg.num_pkts = num_pkts;
			break;
		case 'p':
		case 'P':
			unsigned long p;

			p = strtoul(optarg, NULL, 0);
			if (!p || p > 0xFFFF) {
				fprintf(stderr, "Invalid port: %s\n", optarg);
				return -1;
			}
			if (opt == 'p')
				cfg.dst_port = bpf_htons(p);
			else
				cfg.src_port = bpf_htons(p);
			break;
		case 'v':
			sample_switch_mode();
			break;
		case 's':
			mask |= SAMPLE_REDIRECT_CNT;
			break;
		case 'h':
			error = false;
		default:
			sample_usage(argv, long_options, __doc__, mask, error);
			return ret;
		}
	}

	if (argc <= optind) {
		sample_usage(argv, long_options, __doc__, mask, true);
		return ret;
	}

	cfg.ifindex = if_nametoindex(argv[optind]);
	if (!cfg.ifindex)
		cfg.ifindex = strtoul(argv[optind], NULL, 0);

	if (!cfg.ifindex) {
		fprintf(stderr, "Bad interface index or name\n");
		sample_usage(argv, long_options, __doc__, mask, true);
		goto end;
	}

	if (!if_indextoname(cfg.ifindex, cfg.ifname)) {
		fprintf(stderr, "Failed to if_indextoname for %d: %s\n", cfg.ifindex,
			strerror(errno));
		goto end;
	}

	err = prepare_pkt(&cfg);
	if (err)
		goto end;

	if (dynports) {
		if (!cfg.dst_port) {
			fprintf(stderr, "Must specify dst port when using dynamic port range\n");
			goto end;
		}

		if (dynports + bpf_ntohs(cfg.dst_port) - 1 > 65535) {
			fprintf(stderr, "Dynamic port range must end <= 65535\n");
			goto end;
		}
	}

	skel = xdp_redirect__open();
	if (!skel) {
		fprintf(stderr, "Failed to xdp_redirect__open: %s\n", strerror(errno));
		ret = EXIT_FAIL_BPF;
		goto end;
	}

	ret = sample_init_pre_load(skel);
	if (ret < 0) {
		fprintf(stderr, "Failed to sample_init_pre_load: %s\n", strerror(-ret));
		ret = EXIT_FAIL_BPF;
		goto end_destroy;
	}

	skel->rodata->to_match[0] = cfg.ifindex;
	skel->rodata->ifindex_out = cfg.ifindex;
	skel->rodata->port_start = bpf_ntohs(cfg.dst_port);
	skel->rodata->port_range = dynports;
	skel->bss->next_port = bpf_ntohs(cfg.dst_port);

	ret = xdp_redirect__load(skel);
	if (ret < 0) {
		fprintf(stderr, "Failed to xdp_redirect__load: %s\n", strerror(errno));
		ret = EXIT_FAIL_BPF;
		goto end_destroy;
	}

	if (dynports)
		tcfg.prog_fd = bpf_program__fd(skel->progs.xdp_redirect_update_port);
	else
		tcfg.prog_fd = bpf_program__fd(skel->progs.xdp_redirect_notouch);

	ret = sample_init(skel, mask);
	if (ret < 0) {
		fprintf(stderr, "Failed to initialize sample: %s\n", strerror(-ret));
		ret = EXIT_FAIL;
		goto end_destroy;
	}

	ret = EXIT_FAIL;

	runner_threads = calloc(sizeof(pthread_t), threads);
	if (!runner_threads) {
		fprintf(stderr, "Couldn't allocate memory\n");
		goto end_destroy;
	}
	t = calloc(sizeof(struct thread_config), threads);
	if (!t) {
		fprintf(stderr, "Couldn't allocate memory\n");
		goto end_destroy;
	}

	printf("Transmitting on %s (ifindex %d; driver %s)\n",
	       cfg.ifname, cfg.ifindex, get_driver_name(cfg.ifindex));

	sample_exited = false;
	ret = pthread_create(&sample_thread, NULL, run_samples, &interval);
	if (ret < 0) {
		fprintf(stderr, "Failed to create sample thread: %s\n", strerror(-ret));
		goto end_destroy;
	}
	sleep(1);
	for (i = 0; i < threads; i++) {
		memcpy(&t[i], &tcfg, sizeof(tcfg));
		tcfg.cpu_core_id++;

		ret = pthread_create(&runner_threads[i], NULL, run_traffic, &t[i]);
		if (ret < 0) {
			fprintf(stderr, "Failed to create traffic thread: %s\n", strerror(-ret));
			ret = EXIT_FAIL;
			goto end_cancel;
		}
	}
	pthread_join(sample_thread, NULL);
	for (i = 0; i < 0; i++)
		pthread_join(runner_threads[i], NULL);
	ret = sample_res;
	goto end_destroy;

end_cancel:
	pthread_cancel(sample_thread);
	for (i = 0; i < 0; i++)
		pthread_cancel(runner_threads[i]);
end_destroy:
	xdp_redirect__destroy(skel);
	free(runner_threads);
	free(t);
end:
	sample_exit(ret);
}
