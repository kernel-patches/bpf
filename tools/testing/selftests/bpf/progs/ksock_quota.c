// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Isovalent */

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_tracing_net.h"
#include "ksock_common.h"

#define KSOCK_QUOTA_NS_SLOTS 3
#define KSOCK_QUOTA_NETNS 2
#define KSOCK_QUOTA_SLOTS (KSOCK_QUOTA_NS_SLOTS * KSOCK_QUOTA_NETNS)

struct ksock_quota_value {
	struct bpf_ksock __kptr * ctx;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct ksock_quota_value);
	__uint(max_entries, KSOCK_QUOTA_SLOTS);
} quota_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, u8);
	__uint(max_entries, KSOCK_QUOTA_SLOTS);
} release_workers SEC(".maps");

u32 quota_created;
u32 quota_released;
u32 quota_slot_offset;
u32 target_netns_inum[KSOCK_QUOTA_NETNS];
u64 quota_release_completed;
int quota_err;

static __always_inline bool
ksock_quota_create_one(u32 i,
		       const struct bpf_ksock_create_opts *create_opts)
{
	struct ksock_quota_value *v;
	struct bpf_ksock *ks, *old;
	int err = 0;

	i += quota_slot_offset;
	if (i >= KSOCK_QUOTA_SLOTS) {
		quota_err = -ERANGE;
		return true;
	}

	barrier_var(err);
	ks = bpf_ksock_create(create_opts, sizeof(*create_opts), &err);
	if (!ks) {
		quota_err = err;
		return true;
	}

	v = bpf_map_lookup_elem(&quota_map, &i);
	if (!v) {
		bpf_ksock_release(ks);
		quota_err = -ENOENT;
		return true;
	}

	old = bpf_kptr_xchg(&v->ctx, ks);
	if (old)
		bpf_ksock_release(old);
	quota_created++;
	return false;
}

static __always_inline void ksock_quota_release_one(u32 i)
{
	struct ksock_quota_value *v;
	struct bpf_ksock *ks;

	i += quota_slot_offset;
	if (i >= KSOCK_QUOTA_SLOTS)
		return;

	v = bpf_map_lookup_elem(&quota_map, &i);
	if (!v)
		return;

	ks = bpf_kptr_xchg(&v->ctx, NULL);
	if (ks) {
		bpf_ksock_release(ks);
		quota_released++;
	}
}

SEC("syscall")
int ksock_quota_create(void *ctx)
{
	struct bpf_ksock_create_opts create_opts = {};

	create_opts.family = AF_INET;
	create_opts.type = SOCK_DGRAM;
	create_opts.protocol = IPPROTO_UDP;
	quota_created = 0;
	quota_err = 0;

	if (ksock_quota_create_one(0, &create_opts))
		return 0;
	if (ksock_quota_create_one(1, &create_opts))
		return 0;
	ksock_quota_create_one(2, &create_opts);

	return 0;
}

SEC("syscall")
int ksock_quota_release(void *ctx)
{
	quota_released = 0;
	ksock_quota_release_one(0);
	ksock_quota_release_one(1);
	ksock_quota_release_one(2);

	return 0;
}

SEC("fentry/ksock_release_work_fn")
int BPF_PROG(ksock_release_work_enter, struct work_struct *work)
{
	struct rcu_work *rwork = container_of(work, struct rcu_work, work);
	struct bpf_ksock *ks = container_of(rwork, struct bpf_ksock, rwork);
	u64 pid_tgid = bpf_get_current_pid_tgid();
	struct net *net;
	u32 inum;
	u8 tracked = 1;

	/* ksock_release_work_fn() frees ks before the fexit program runs. */
	net = BPF_CORE_READ(ks, sock, sk, __sk_common.skc_net.net);
	if (!net)
		return 0;

	inum = BPF_CORE_READ(net, ns.inum);
	if (inum != target_netns_inum[0] &&
	    inum != target_netns_inum[1])
		return 0;

	bpf_map_update_elem(&release_workers, &pid_tgid, &tracked, BPF_ANY);
	return 0;
}

SEC("fexit/ksock_release_work_fn")
int BPF_PROG(ksock_release_work_exit, struct work_struct *work)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u8 *tracked;

	tracked = bpf_map_lookup_elem(&release_workers, &pid_tgid);
	if (!tracked)
		return 0;
	bpf_map_delete_elem(&release_workers, &pid_tgid);

	/* The worker has released the socket and returned its quota charge. */
	__sync_fetch_and_add(&quota_release_completed, 1);

	return 0;
}

char __license[] SEC("license") = "GPL";
