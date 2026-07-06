// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Isovalent */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "bpf_tracing_net.h"
#include "ksock_common.h"

SEC("syscall")
int ksock_setup(void *ctx)
{
	return do_ksock_setup();
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
