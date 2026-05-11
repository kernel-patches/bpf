// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <linux/bpf.h>
#include <linux/bpf_netpoll.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/netpoll.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <linux/workqueue.h>

#define BPF_NETPOLL_MAX_UDP_CHUNK 1460

/**
 * struct bpf_netpoll - refcounted BPF netpoll context
 * @np:		The underlying netpoll structure.
 * @usage:	Reference counter.
 * @rwork:	RCU work for deferred cleanup (netpoll_cleanup sleeps).
 */
struct bpf_netpoll {
	struct netpoll np;
	refcount_t usage;
	struct rcu_work rwork;
};

static void netpoll_release_work_fn(struct work_struct *work)
{
	struct bpf_netpoll *bnp = container_of(to_rcu_work(work),
					       struct bpf_netpoll, rwork);

	netpoll_cleanup(&bnp->np);
	kfree(bnp);
}

__bpf_kfunc_start_defs();

/**
 * bpf_netpoll_create() - Create a BPF netpoll context for sending UDP.
 *
 * Allocates and sets up a netpoll context that can be used to send UDP
 * packets from BPF programs. The returned context must either be stored
 * in a map as a kptr, or freed with bpf_netpoll_release().
 *
 * This function calls netpoll_setup() which takes rtnl_lock and may
 * sleep, so it can only be used in sleepable BPF programs (SYSCALL).
 *
 * @opts:	Pointer to struct bpf_netpoll_opts with connection parameters.
 * @opts__sz:	Size of the opts struct.
 * @err:	Integer to store error code when NULL is returned.
 */
__bpf_kfunc struct bpf_netpoll *
bpf_netpoll_create(const struct bpf_netpoll_opts *opts, u32 opts__sz, int *err)
{
	struct bpf_netpoll *bnp;

	if (!opts || opts__sz != sizeof(struct bpf_netpoll_opts)) {
		*err = -EINVAL;
		return NULL;
	}

	if (opts->reserved) {
		*err = -EINVAL;
		return NULL;
	}

	bnp = kzalloc_obj(*bnp);
	if (!bnp) {
		*err = -ENOMEM;
		return NULL;
	}

	bnp->np.name = "bpf_netpoll";
	strscpy(bnp->np.dev_name, opts->dev_name, IFNAMSIZ);
	bnp->np.local_port = opts->local_port;
	bnp->np.remote_port = opts->remote_port;
	memcpy(bnp->np.remote_mac, opts->remote_mac, ETH_ALEN);

	bnp->np.ipv6 = !!opts->ipv6;
	if (opts->ipv6) {
		memcpy(&bnp->np.local_ip.in6, opts->local_ip6,
		       sizeof(struct in6_addr));
		memcpy(&bnp->np.remote_ip.in6, opts->remote_ip6,
		       sizeof(struct in6_addr));
	} else {
		bnp->np.local_ip.ip = opts->local_ip;
		bnp->np.remote_ip.ip = opts->remote_ip;
	}

	*err = netpoll_setup(&bnp->np);
	if (*err) {
		kfree(bnp);
		return NULL;
	}

	refcount_set(&bnp->usage, 1);
	return bnp;
}

/**
 * bpf_netpoll_acquire() - Acquire a reference to a BPF netpoll context.
 * @bnp:	The BPF netpoll context to acquire. Must be a trusted pointer.
 *
 * The acquired context must either be stored in a map as a kptr, or
 * freed with bpf_netpoll_release().
 */
__bpf_kfunc struct bpf_netpoll *
bpf_netpoll_acquire(struct bpf_netpoll *bnp)
{
	if (!refcount_inc_not_zero(&bnp->usage))
		return NULL;
	return bnp;
}

/**
 * bpf_netpoll_release() - Release a BPF netpoll context.
 * @bnp:	The BPF netpoll context to release.
 *
 * When the final reference is released, the netpoll context is cleaned
 * up via queue_rcu_work() (since netpoll_cleanup takes rtnl_lock and
 * must run in process context).
 */
__bpf_kfunc void bpf_netpoll_release(struct bpf_netpoll *bnp)
{
	if (refcount_dec_and_test(&bnp->usage)) {
		INIT_RCU_WORK(&bnp->rwork, netpoll_release_work_fn);
		queue_rcu_work(system_wq, &bnp->rwork);
	}
}

__bpf_kfunc void bpf_netpoll_release_dtor(void *bnp)
{
	bpf_netpoll_release(bnp);
}
CFI_NOSEAL(bpf_netpoll_release_dtor);

/**
 * bpf_netpoll_send_udp() - Send a UDP packet via netpoll.
 * @bnp:	The BPF netpoll context. Must be an RCU-protected pointer.
 * @data:	Pointer to the data to send.
 * @data__sz:	Size of the data to send (max 1460 bytes).
 *
 * Sends a UDP packet using the netpoll infrastructure. Can be called
 * from any context (process, softirq, hardirq).
 *
 * Return: 0 on success, 1 (NET_XMIT_DROP) on drop, negative errno on error.
 */
__bpf_kfunc int bpf_netpoll_send_udp(struct bpf_netpoll *bnp,
				     const void *data, u32 data__sz)
{
	unsigned long flags;
	int ret;

	if (data__sz > BPF_NETPOLL_MAX_UDP_CHUNK)
		return -E2BIG;

	local_irq_save(flags);
	ret = netpoll_send_udp(&bnp->np, data, data__sz);
	local_irq_restore(flags);

	return ret;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(netpoll_init_kfunc_btf_ids)
BTF_ID_FLAGS(func, bpf_netpoll_create, KF_ACQUIRE | KF_RET_NULL | KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_netpoll_release, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_netpoll_acquire, KF_ACQUIRE | KF_RCU | KF_RET_NULL)
BTF_KFUNCS_END(netpoll_init_kfunc_btf_ids)

static const struct btf_kfunc_id_set netpoll_init_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &netpoll_init_kfunc_btf_ids,
};

BTF_KFUNCS_START(netpoll_kfunc_btf_ids)
BTF_ID_FLAGS(func, bpf_netpoll_send_udp, KF_RCU)
BTF_KFUNCS_END(netpoll_kfunc_btf_ids)

static const struct btf_kfunc_id_set netpoll_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &netpoll_kfunc_btf_ids,
};

BTF_ID_LIST(bpf_netpoll_dtor_ids)
BTF_ID(struct, bpf_netpoll)
BTF_ID(func, bpf_netpoll_release_dtor)

static int __init bpf_netpoll_kfunc_init(void)
{
	int ret;
	const struct btf_id_dtor_kfunc bpf_netpoll_dtors[] = {
		{
			.btf_id       = bpf_netpoll_dtor_ids[0],
			.kfunc_btf_id = bpf_netpoll_dtor_ids[1],
		},
	};

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					&netpoll_init_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC,
					       &netpoll_kfunc_set);
	return ret ?: register_btf_id_dtor_kfuncs(bpf_netpoll_dtors,
						  ARRAY_SIZE(bpf_netpoll_dtors),
						  THIS_MODULE);
}

late_initcall(bpf_netpoll_kfunc_init);
