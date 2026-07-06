// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 Isovalent */

#include <linux/bpf.h>
#include <linux/bpf_ksock.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/cache.h>
#include <linux/hash.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/list_bl.h>
#include <linux/net.h>
#include <linux/refcount.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <linux/unaligned.h>
#include <linux/workqueue.h>
#include <linux/ip.h>
#include <net/ipv6.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/sock.h>

/**
 * struct bpf_ksock - refcounted BPF kernel socket context
 * @sock:	The underlying kernel socket.
 * @usage:	Reference counter.
 * @rwork:	RCU work for deferred cleanup (sock_release may sleep).
 */
struct bpf_ksock {
	struct socket *sock;
	refcount_t usage;
	struct rcu_work rwork;
};

struct bpf_ksock_send_guard {
	struct hlist_bl_node node;
	struct task_struct *task;
};

#define BPF_KSOCK_SEND_GUARD_HASH_BITS 6

struct bpf_ksock_send_bucket {
	struct hlist_bl_head head;
} ____cacheline_aligned_in_smp;

static struct bpf_ksock_send_bucket
	bpf_ksock_send_buckets[1 << BPF_KSOCK_SEND_GUARD_HASH_BITS];

static struct bpf_ksock_send_bucket *
bpf_ksock_send_bucket(const struct task_struct *task)
{
	u32 bucket_idx = hash_ptr(task, BPF_KSOCK_SEND_GUARD_HASH_BITS);

	return &bpf_ksock_send_buckets[bucket_idx];
}

static bool bpf_ksock_send_enter(struct bpf_ksock_send_guard *guard)
{
	struct bpf_ksock_send_guard *entry;
	struct hlist_bl_node *pos;
	struct bpf_ksock_send_bucket *bucket;

	bucket = bpf_ksock_send_bucket(current);
	hlist_bl_lock(&bucket->head);
	hlist_bl_for_each_entry(entry, pos, &bucket->head, node) {
		if (entry->task == current) {
			hlist_bl_unlock(&bucket->head);
			return false;
		}
	}

	guard->task = current;
	INIT_HLIST_BL_NODE(&guard->node);
	hlist_bl_add_head(&guard->node, &bucket->head);
	hlist_bl_unlock(&bucket->head);
	return true;
}

static void bpf_ksock_send_exit(struct bpf_ksock_send_guard *guard)
{
	struct bpf_ksock_send_bucket *bucket;

	bucket = bpf_ksock_send_bucket(guard->task);
	hlist_bl_lock(&bucket->head);
	hlist_bl_del(&guard->node);
	hlist_bl_unlock(&bucket->head);
}

struct bpf_ksock_net {
	atomic_t count;
};

static unsigned int bpf_ksock_net_id;
int sysctl_bpf_ksock_max __read_mostly = BPF_KSOCK_MAX_DEFAULT;

static struct bpf_ksock_net *bpf_ksock_pernet(const struct net *net)
{
	return net_generic(net, bpf_ksock_net_id);
}

static struct pernet_operations bpf_ksock_net_ops = {
	.id = &bpf_ksock_net_id,
	.size = sizeof(struct bpf_ksock_net),
};

static bool bpf_ksock_net_try_charge(struct net *net)
{
	struct bpf_ksock_net *kn = bpf_ksock_pernet(net);
	int count = atomic_read(&kn->count);
	int max;

	do {
		max = READ_ONCE(sysctl_bpf_ksock_max);
		if (count >= max)
			return false;
	} while (!atomic_try_cmpxchg(&kn->count, &count, count + 1));

	return true;
}

static void bpf_ksock_net_uncharge(struct net *net)
{
	struct bpf_ksock_net *kn = bpf_ksock_pernet(net);

	WARN_ON_ONCE(atomic_dec_return(&kn->count) < 0);
}

static void ksock_release_work_fn(struct work_struct *work)
{
	struct bpf_ksock *ks =
		container_of(to_rcu_work(work), struct bpf_ksock, rwork);
	struct net *net = get_net(sock_net(ks->sock->sk));

	sock_release(ks->sock);
	bpf_ksock_net_uncharge(net);
	put_net(net);
	kfree(ks);
}

static int bpf_ksock_get_addr(const struct bpf_ksock_addr_opts *opts,
			      u32 opts__sz, struct sockaddr_storage *addr)
{
	struct bpf_ksock_addr_opts opts_copy;

	if (!opts || opts__sz != sizeof(*opts))
		return -EINVAL;

	/* Kfunc memory arguments are not guaranteed to be naturally aligned. */
	memcpy(&opts_copy, opts, sizeof(opts_copy));

	if (opts_copy.reserved)
		return -EINVAL;

	switch (opts_copy.family) {
	case AF_INET: {
		struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;

		if (opts_copy.scope_id)
			return -EINVAL;

		*addr4 = (struct sockaddr_in){
			.sin_family = AF_INET,
			.sin_port = htons(opts_copy.port),
			.sin_addr.s_addr = opts_copy.ipv4_addr,
		};
		return sizeof(*addr4);
	}
#if IS_ENABLED(CONFIG_IPV6)
	case AF_INET6: {
		struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;

		*addr6 = (struct sockaddr_in6){
			.sin6_family = AF_INET6,
			.sin6_port = htons(opts_copy.port),
			.sin6_scope_id = opts_copy.scope_id,
		};
		memcpy(&addr6->sin6_addr, opts_copy.ipv6_addr,
		       sizeof(struct in6_addr));
		return sizeof(*addr6);
	}
#endif
	default:
		return -EAFNOSUPPORT;
	}
}

static bool bpf_ksock_has_user_task_context(void)
{
	/*
	 * Task work can run from do_exit() after exit_nsproxy_namespaces()
	 * cleared current->nsproxy, while current is still not a kthread.
	 */
	return !(current->flags & PF_KTHREAD) && current->nsproxy;
}

__bpf_kfunc_start_defs();

/**
 * bpf_ksock_create() - Create a BPF kernel socket.
 *
 * Allocates and creates a kernel socket.
 * The socket is charged against the active network namespace's BPF kernel
 * socket quota.
 *
 * The returned context must either be stored in a map as a kptr, or
 * freed with bpf_ksock_release().
 *
 * This function may sleep (sock_create), so it can only be used
 * in sleepable BPF programs (SYSCALL).
 * It cannot be called from a BPF workqueue callback because that callback
 * does not retain the invoking task's namespace or security context.
 *
 * @opts:	Pointer to struct bpf_ksock_create_opts with socket parameters.
 * @opts__sz:	Size of the opts struct.
 * @err__uninit:	Integer to store error code when NULL is returned.
 */
__bpf_kfunc struct bpf_ksock *
bpf_ksock_create(const struct bpf_ksock_create_opts *opts, u32 opts__sz,
		 int *err__uninit)
{
	struct bpf_ksock_create_opts opts_copy;
	struct bpf_ksock *ks;
	struct net *net;
	int err;

	/*
	 * sock_create() derives the network namespace, credentials, and cgroup
	 * from current. Kernel threads, including BPF workqueue callbacks, do
	 * not carry the context of the task that invoked the BPF program.
	 */
	if (!bpf_ksock_has_user_task_context()) {
		err = -EOPNOTSUPP;
		goto err_out;
	}

	if (!opts || opts__sz != sizeof(struct bpf_ksock_create_opts)) {
		err = -EINVAL;
		goto err_out;
	}

	opts_copy = (struct bpf_ksock_create_opts){
		.family = READ_ONCE(opts->family),
		.type = READ_ONCE(opts->type),
		.protocol = READ_ONCE(opts->protocol),
		.reserved = READ_ONCE(opts->reserved),
	};

	if (opts_copy.reserved) {
		err = -EINVAL;
		goto err_out;
	}

	if (opts_copy.family != AF_INET && opts_copy.family != AF_INET6) {
		err = -EAFNOSUPPORT;
		goto err_out;
	}

	if (opts_copy.type != SOCK_DGRAM) {
		err = -EPROTONOSUPPORT;
		goto err_out;
	}

	if (opts_copy.protocol != IPPROTO_UDP && opts_copy.protocol != 0) {
		err = -EPROTONOSUPPORT;
		goto err_out;
	}

	ks = kzalloc_obj(*ks);
	if (!ks) {
		err = -ENOMEM;
		goto err_out;
	}

	net = current->nsproxy->net_ns;
	if (!bpf_ksock_net_try_charge(net)) {
		err = -ENOSPC;
		goto err_free;
	}

	/*
	 * Use the normal current-task socket path so LSM/cgroup policy,
	 * socket labels, and the active netns reference match a socket(2)
	 * created by the BPF program's caller.
	 */
	err = sock_create(opts_copy.family, opts_copy.type, opts_copy.protocol,
			  &ks->sock);
	if (err)
		goto err_uncharge;

	ks->sock->sk->sk_rcvbuf = SOCK_MIN_RCVBUF;
	ks->sock->sk->sk_userlocks |= SOCK_RCVBUF_LOCK;

	refcount_set(&ks->usage, 1);
	put_unaligned(0, err__uninit);
	return ks;

err_uncharge:
	bpf_ksock_net_uncharge(net);
err_free:
	kfree(ks);
err_out:
	put_unaligned(err, err__uninit);
	return NULL;
}

/**
 * bpf_ksock_bind() - Bind a BPF kernel socket to a local address.
 * @ks:		The BPF kernel socket context.
 * @opts:	Pointer to struct bpf_ksock_addr_opts with local address.
 * @opts__sz:	Size of the opts struct.
 *
 * Binds the socket to the specified local address and port.
 * This is optional; if not called, the kernel will auto-assign.
 *
 * This function may sleep while binding the socket, so it can only be used in
 * sleepable BPF programs (SYSCALL).
 *
 * Return: 0 on success, negative errno on error.
 */
__bpf_kfunc int bpf_ksock_bind(struct bpf_ksock *ks,
			       const struct bpf_ksock_addr_opts *opts,
			       u32 opts__sz)
{
	struct sockaddr_storage addr = {};
	int addrlen;

	if (!bpf_ksock_has_user_task_context())
		return -EOPNOTSUPP;

	addrlen = bpf_ksock_get_addr(opts, opts__sz, &addr);
	if (addrlen < 0)
		return addrlen;

	return __sys_bind_socket(ks->sock, &addr, addrlen);
}

/**
 * bpf_ksock_connect() - Connect a BPF kernel socket to a remote address.
 * @ks:		The BPF kernel socket context.
 * @opts:	Pointer to struct bpf_ksock_addr_opts with remote address.
 * @opts__sz:	Size of the opts struct.
 *
 * Connects the socket to the specified remote address and port.
 *
 * This function may sleep while connecting the socket, so it can only be used
 * in sleepable BPF programs (SYSCALL).
 *
 * Return: 0 on success, negative errno on error.
 */
__bpf_kfunc int bpf_ksock_connect(struct bpf_ksock *ks,
				  const struct bpf_ksock_addr_opts *opts,
				  u32 opts__sz)
{
	struct sockaddr_storage addr = {};
	int addrlen;

	if (!bpf_ksock_has_user_task_context())
		return -EOPNOTSUPP;

	addrlen = bpf_ksock_get_addr(opts, opts__sz, &addr);
	if (addrlen < 0)
		return addrlen;

	return __sys_connect_socket(ks->sock, &addr, addrlen, 0);
}

/**
 * bpf_ksock_acquire() - Acquire a reference to a BPF kernel socket.
 * @ks:	The BPF kernel socket context to acquire. Must be a
 *	trusted pointer (e.g. RCU-protected kptr from a map).
 *
 * The acquired context must either be stored in a map as a kptr, or
 * freed with bpf_ksock_release().
 */
__bpf_kfunc struct bpf_ksock *bpf_ksock_acquire(struct bpf_ksock *ks)
{
	if (!refcount_inc_not_zero(&ks->usage))
		return NULL;
	return ks;
}

/**
 * bpf_ksock_release() - Release a BPF kernel socket.
 * @ks:	The BPF kernel socket context to release.
 *
 * When the final reference is released, the socket is cleaned up via
 * queue_rcu_work() (since sock_release may sleep).
 */
__bpf_kfunc void bpf_ksock_release(struct bpf_ksock *ks)
{
	if (refcount_dec_and_test(&ks->usage)) {
		INIT_RCU_WORK(&ks->rwork, ksock_release_work_fn);
		queue_rcu_work(system_dfl_wq, &ks->rwork);
	}
}

__bpf_kfunc void bpf_ksock_release_dtor(void *ks)
{
	bpf_ksock_release(ks);
}
CFI_NOSEAL(bpf_ksock_release_dtor);

/**
 * bpf_ksock_send() - Send data through a BPF kernel socket.
 * @ks:		The BPF kernel socket context. Must be an acquired reference.
 * @data:	Pointer to the data to send.
 * @data__sz:	Size of the data to send (max 65535 bytes).
 *
 * Sends data on a connected socket, best-effort and nonblocking. This may sleep
 * (kernel_sendmsg), so it can only be called from sleepable BPF programs.
 *
 * Return: Number of bytes sent on success, negative errno on error.
 */
__bpf_kfunc int bpf_ksock_send(struct bpf_ksock *ks, const void *data,
			       u32 data__sz)
{
	struct bpf_ksock_send_guard guard;
	struct msghdr msg = {
		.msg_flags = MSG_DONTWAIT,
	};
	struct kvec iov = {
		.iov_base = (void *)data,
		.iov_len = data__sz,
	};
	int ret;

	if (!bpf_ksock_has_user_task_context())
		return -EOPNOTSUPP;

	/* Early check for UDP. Exact limits enforced by kernel_sendmsg(). */
	if (data__sz > IP_MAX_MTU)
		return -EMSGSIZE;

	if (!bpf_ksock_send_enter(&guard))
		return -EBUSY;

	ret = kernel_sendmsg(ks->sock, &msg, &iov, 1, data__sz);
	bpf_ksock_send_exit(&guard);

	return ret;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(ksock_init_kfunc_btf_ids)
BTF_ID_FLAGS(func, bpf_ksock_create, KF_ACQUIRE | KF_RET_NULL | KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ksock_bind, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ksock_connect, KF_SLEEPABLE)
BTF_KFUNCS_END(ksock_init_kfunc_btf_ids)

static const struct btf_kfunc_id_set ksock_init_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &ksock_init_kfunc_btf_ids,
};

BTF_KFUNCS_START(ksock_kfunc_btf_ids)
BTF_ID_FLAGS(func, bpf_ksock_release, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_ksock_acquire, KF_ACQUIRE | KF_RCU | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_ksock_send, KF_SLEEPABLE)
BTF_KFUNCS_END(ksock_kfunc_btf_ids)

static int bpf_ksock_kfunc_filter(const struct bpf_prog *prog, u32 kfunc_id)
{
	if (!btf_id_set8_contains(&ksock_kfunc_btf_ids, kfunc_id) ||
	    prog->type == BPF_PROG_TYPE_SYSCALL ||
	    prog->type == BPF_PROG_TYPE_LSM)
		return 0;

	return -EACCES;
}

static const struct btf_kfunc_id_set ksock_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &ksock_kfunc_btf_ids,
	.filter = bpf_ksock_kfunc_filter,
};

BTF_ID_LIST(bpf_ksock_dtor_ids)
BTF_ID(struct, bpf_ksock)
BTF_ID(func, bpf_ksock_release_dtor)

static int __init bpf_ksock_kfunc_init(void)
{
	int ret;
	const struct btf_id_dtor_kfunc bpf_ksock_dtors[] = {
		{
			.btf_id = bpf_ksock_dtor_ids[0],
			.kfunc_btf_id = bpf_ksock_dtor_ids[1],
		},
	};

	ret = register_pernet_subsys(&bpf_ksock_net_ops);
	if (ret)
		return ret;

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					&ksock_init_kfunc_set);
	if (ret) {
		unregister_pernet_subsys(&bpf_ksock_net_ops);
		return ret;
	}

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					&ksock_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_LSM,
					       &ksock_kfunc_set);
	return ret = ret ?: register_btf_id_dtor_kfuncs(bpf_ksock_dtors,
						 ARRAY_SIZE(bpf_ksock_dtors),
						 THIS_MODULE);
}

late_initcall(bpf_ksock_kfunc_init);
