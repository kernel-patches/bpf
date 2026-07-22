// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Isovalent */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "bpf_tracing_net.h"
#include "ksock_common.h"

__be32 ipv4_remote;
__u16 remote_port;

char send_data[32] = "hello from bpf ksock";

SEC("syscall")
int ksock_setup(void *ctx)
{
	struct bpf_ksock_create_opts create_opts = {};
	struct bpf_ksock_addr_opts addr_opts = {};
	struct bpf_ksock *ks;
	int err = 0;

	create_opts.family = AF_INET;
	create_opts.type = SOCK_DGRAM;
	create_opts.protocol = IPPROTO_UDP;

	ks = bpf_ksock_create(&create_opts, sizeof(create_opts), &err);
	if (!ks)
		return err;

	addr_opts.family = AF_INET;
	addr_opts.port = remote_port;
	addr_opts.ipv4_addr = ipv4_remote;

	err = bpf_ksock_connect(ks, &addr_opts, sizeof(addr_opts));
	if (err) {
		bpf_ksock_release(ks);
		return err;
	}

	err = ksock_ctx_insert(ks);
	if (err && err != -EEXIST)
		return err;
	return 0;
}

SEC("syscall")
int ksock_send(void *ctx)
{
	struct __ksock_ctx_value *v;
	struct bpf_ksock *ks;
	int send = -1;

	v = ksock_ctx_value_lookup();
	if (!v)
		return -ENOENT;

	ks = bpf_kptr_xchg(&v->ctx, NULL);
	if (!ks)
		return -ENOENT;

	send = bpf_ksock_send(ks, send_data, sizeof(send_data));
	bpf_ksock_release(ks);
	return send;
}

char __license[] SEC("license") = "GPL";
