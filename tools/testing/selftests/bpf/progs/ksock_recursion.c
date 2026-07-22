// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Isovalent */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "bpf_tracing_net.h"
#include "ksock_common.h"

void bpf_rcu_read_lock(void) __ksym;
void bpf_rcu_read_unlock(void) __ksym;

int target_pid;
int trigger_send;

unsigned int rec_count;
int rec_kfunc_rets[] = { -1, -1 };

SEC("syscall")
int ksock_setup(void *ctx)
{
	return do_ksock_setup();
}

SEC("lsm.s/socket_sendmsg")
int BPF_PROG(ksock_socket_sendmsg, struct socket *sock, struct msghdr *msg,
	     int size, int ret)
{
	struct __ksock_ctx_value *v;
	struct bpf_ksock *ks, *tmp;
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	int kfunc_ret;

	if (ret || !trigger_send || pid != target_pid)
		return ret;

	v = ksock_ctx_value_lookup();
	if (!v) {
		kfunc_ret = -ENOENT;
		goto out;
	}

	ks = NULL;
	bpf_rcu_read_lock();
	tmp = v->ctx;
	if (tmp)
		ks = bpf_ksock_acquire(tmp);
	bpf_rcu_read_unlock();

	if (!ks) {
		kfunc_ret = -ENOENT;
		goto out;
	}

	kfunc_ret = bpf_ksock_send(ks, send_data, sizeof(send_data));
	bpf_ksock_release(ks);

out:
	rec_kfunc_rets[rec_count & 1] = kfunc_ret;
	__sync_fetch_and_add(&rec_count, 1);

	if (kfunc_ret != -EBUSY)
		trigger_send = 0;

	return ret;
}

char __license[] SEC("license") = "GPL";
