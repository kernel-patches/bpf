// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
/* Copyright (c) 2026 Isovalent. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "bpf_tracing_net.h"
#include "netpoll_common.h"

/* Globals for passing config from userspace */
char dev_name[16] = {};
__be32 remote_ip;
__u16 local_port;
__u16 remote_port;
__u8 remote_mac[6] = {};

/* Results */
int status;
int send_status;
int trigger_send;
char driver_xmit[64];

char send_data[64] = "hello from bpf netpoll";

/* SYSCALL prog: set up the netpoll context */
SEC("syscall")
int netpoll_setup_test(void *ctx)
{
	struct bpf_netpoll_opts opts = {};
	struct bpf_netpoll *bnp;
	int err = 0;

	status = 0;

	__builtin_memcpy(opts.dev_name, dev_name, 16);
	opts.remote_ip = remote_ip;
	opts.local_port = local_port;
	opts.remote_port = remote_port;
	__builtin_memcpy(opts.remote_mac, remote_mac, 6);

	bnp = bpf_netpoll_create(&opts, sizeof(opts), &err);
	if (!bnp) {
		status = err;
		return 0;
	}

	err = netpoll_ctx_insert(bnp);
	if (err && err != -EEXIST)
		status = err;
	return 0;
}

/* LSM prog: send UDP via the stored netpoll context */
SEC("lsm/file_open")
int BPF_PROG(netpoll_send_test, struct file *file)
{
	struct __netpoll_ctx_value *v;
	struct bpf_netpoll *bnp;

	if (!trigger_send)
		return 0;

	trigger_send = 0;
	send_status = -ENOENT;

	v = netpoll_ctx_value_lookup();
	if (!v)
		return 0;

	bpf_rcu_read_lock();
	bnp = v->ctx;
	if (!bnp) {
		bpf_rcu_read_unlock();
		return 0;
	}

	send_status = bpf_netpoll_send_udp(bnp, send_data, sizeof(send_data));
	bpf_rcu_read_unlock();
	return 0;
}

/* Fentry prog: hook the dummy driver xmit */
SEC("fentry/dummy_xmit")
int BPF_PROG(netpoll_dummy_xmit, struct sk_buff *skb, struct net_device *dev)
{
	unsigned char *data;
	struct ethhdr eth;
	struct iphdr ip;
	struct udphdr udp;

	if (bpf_probe_read_kernel(&data, sizeof(data), &skb->data) < 0)
		return 0;
	if (!data)
		return 0;

	if (bpf_probe_read_kernel(&eth, sizeof(eth), data) < 0)
		return 0;
	if (eth.h_proto != bpf_htons(ETH_P_IP))
		return 0;

	if (bpf_probe_read_kernel(&ip, sizeof(ip), data + sizeof(struct ethhdr)) < 0)
		return 0;
	if (ip.protocol != IPPROTO_UDP)
		return 0;

	if (bpf_probe_read_kernel(&udp, sizeof(udp), data + sizeof(struct ethhdr) + (ip.ihl * 4)) < 0)
		return 0;
	if (udp.dest != bpf_htons(remote_port))
		return 0;
	if (bpf_probe_read_kernel(&driver_xmit, sizeof(driver_xmit), data + sizeof(struct ethhdr) + (ip.ihl * 4) + sizeof(struct udphdr)) < 0)
		return 0;

	return 0;
}

char __license[] SEC("license") = "GPL";
