// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

#define LS_VAL_WORDS	4
/* Maps that getsockopt_enter gets values from */
#define NR_MAPS		4

struct ls_val {
	__u64 w[LS_VAL_WORDS];
};

/* User space sets BPF_F_INLINE_VALUE on the *_inline maps before load */
#define STORAGE_MAP(name, map_type)				\
	struct {						\
		__uint(type, map_type);				\
		__uint(map_flags, BPF_F_NO_PREALLOC);		\
		__type(key, int);				\
		__type(value, struct ls_val);			\
	} name SEC(".maps")

STORAGE_MAP(sk_inline, BPF_MAP_TYPE_SK_STORAGE);
STORAGE_MAP(sk_normal, BPF_MAP_TYPE_SK_STORAGE);
STORAGE_MAP(task_inline, BPF_MAP_TYPE_TASK_STORAGE);
STORAGE_MAP(task_normal, BPF_MAP_TYPE_TASK_STORAGE);
/* User space can replace it with a map of a bigger value */
STORAGE_MAP(sk_reuse, BPF_MAP_TYPE_SK_STORAGE);

int target_tid;
__u64 get_flags;
bool use_init;
__u64 add;
struct ls_val init;
/* The value that each get saw, in the order of the maps above */
struct ls_val seen[NR_MAPS];
int nr_null;
bool reuse_test;
bool do_delete;
/* The return code of each delete, in the order of the maps above */
int del_ret[NR_MAPS];
/*
 * Where each value is: its address, and the address and size of the
 * storage object of its owner. User space checks if the value is in it.
 */
__u64 val_addr[NR_MAPS];
__u64 obj_addr[NR_MAPS];
__u32 obj_size[NR_MAPS];

static __always_inline void record(struct ls_val *v, int i,
				   struct bpf_local_storage *obj)
{
	int j;

	if (!v) {
		nr_null++;
		return;
	}
	val_addr[i] = (__u64)v;
	obj_addr[i] = (__u64)obj;
	obj_size[i] = obj ? obj->obj_size : 0;
	/* Write, so that user space sees that the program found the value */
	for (j = 0; j < LS_VAL_WORDS; j++)
		v->w[j] += add;
	seen[i] = *v;
}

/*
 * Get first, then read the storage pointer of the owner: the get can make
 * the storage object.
 */
static __always_inline void record_sk(void *map, struct sock *sk, void *v, int i)
{
	v = bpf_sk_storage_get(map, sk, v, get_flags);
	record(v, i, sk->sk_bpf_storage);
}

static __always_inline void record_task(void *map, struct task_struct *task,
					void *v, int i)
{
	v = bpf_task_storage_get(map, task, v, get_flags);
	record(v, i, task->bpf_storage);
}

static __always_inline bool is_target(void)
{
	return (__u32)bpf_get_current_pid_tgid() == target_tid;
}

/* getsockopt(SOL_IP) on a TCP socket gives the socket and the task */
SEC("fentry/sock_common_getsockopt")
int BPF_PROG(getsockopt_enter, struct socket *sock)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct sock *sk = sock->sk;
	void *v;

	if (!is_target() || !sk)
		return 0;

	if (reuse_test) {
		/* The value of sk_reuse can be bigger than init: no init */
		record_sk(&sk_reuse, sk, NULL, 0);
		return 0;
	}

	v = use_init ? &init : NULL;
	record_sk(&sk_inline, sk, v, 0);
	record_sk(&sk_normal, sk, v, 1);
	record_task(&task_inline, task, v, 2);
	record_task(&task_normal, task, v, 3);
	if (do_delete) {
		del_ret[0] = bpf_sk_storage_delete(&sk_inline, sk);
		del_ret[1] = bpf_sk_storage_delete(&sk_normal, sk);
		del_ret[2] = bpf_task_storage_delete(&task_inline, task);
		del_ret[3] = bpf_task_storage_delete(&task_normal, task);
	}
	return 0;
}
