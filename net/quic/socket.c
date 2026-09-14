// SPDX-License-Identifier: GPL-2.0-or-later
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Initialization/cleanup for QUIC protocol support.
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#include <net/inet_common.h>
#include <net/tls.h>

#include "socket.h"

static DEFINE_PER_CPU(int, quic_memory_per_cpu_fw_alloc);
static unsigned long quic_memory_pressure;
static atomic_long_t quic_memory_allocated;

static void quic_enter_memory_pressure(struct sock *sk)
{
	WRITE_ONCE(quic_memory_pressure, 1);
}

static void quic_write_space(struct sock *sk)
{
	__poll_t mask = EPOLLOUT | EPOLLWRNORM | EPOLLWRBAND;
	struct socket_wq *wq;

	/* Do not check sock_writeable(). Also wakes stream-open waiters
	 * blocked on stream limits, where sock_writeable() may be false.
	 */
	rcu_read_lock();
	wq = rcu_dereference(sk->sk_wq);
	if (skwq_has_sleeper(wq))
		wake_up_interruptible_sync_poll(&wq->wait, mask);
	sk_wake_async_rcu(sk, SOCK_WAKE_SPACE, POLL_OUT);
	rcu_read_unlock();
}

static void quic_sock_destruct(struct sock *sk)
{
	u8 i;

	/* Deferred crypto free for async encryption/decryption. */
	for (i = 0; i < QUIC_CRYPTO_MAX; i++)
		quic_crypto_free(quic_crypto(sk, i));

	quic_sk_destruct(sk);
}

static int quic_init_sock(struct sock *sk)
{
	u8 i;

	sk->sk_destruct = quic_sock_destruct;
	sk->sk_write_space = quic_write_space;
	sock_set_flag(sk, SOCK_USE_WRITE_QUEUE);

	sk_sockets_allocated_inc(sk);
	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, 1);
	INIT_LIST_HEAD(quic_reqs(sk));

	quic_conn_id_set_init(quic_source(sk), true);
	quic_conn_id_set_init(quic_dest(sk), false);
	quic_path_init(quic_paths(sk));
	quic_cong_init(quic_cong(sk));

	if (quic_stream_init(quic_streams(sk)))
		return -ENOMEM;

	for (i = 0; i < QUIC_PNSPACE_MAX; i++) {
		if (quic_pnspace_init(quic_pnspace(sk, i)))
			return -ENOMEM;
	}

	return 0;
}

static void quic_destroy_sock(struct sock *sk)
{
	u8 i;

	for (i = 0; i < QUIC_PNSPACE_MAX; i++)
		quic_pnspace_free(quic_pnspace(sk, i));

	quic_path_unbind(sk, quic_paths(sk), 0);
	quic_path_unbind(sk, quic_paths(sk), 1);

	quic_conn_id_set_free(quic_source(sk));
	quic_conn_id_set_free(quic_dest(sk));

	quic_stream_free(quic_streams(sk));

	quic_data_free(quic_ticket(sk));
	quic_data_free(quic_token(sk));
	quic_data_free(quic_alpn(sk));

	sk_sockets_allocated_dec(sk);
	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, -1);
}

static int quic_bind(struct sock *sk, struct sockaddr_unsized *addr,
		     int addr_len)
{
	return -EOPNOTSUPP;
}

static int quic_connect(struct sock *sk, struct sockaddr_unsized *addr,
			int addr_len)
{
	return -EOPNOTSUPP;
}

static int quic_hash(struct sock *sk)
{
	return 0;
}

static void quic_unhash(struct sock *sk)
{
}

static int quic_sendmsg(struct sock *sk, struct msghdr *msg, size_t msg_len)
{
	return -EOPNOTSUPP;
}

static int quic_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
			int flags)
{
	return -EOPNOTSUPP;
}

static struct sock *quic_accept(struct sock *sk, struct proto_accept_arg *arg)
{
	arg->err = -EOPNOTSUPP;
	return NULL;
}

static void quic_close(struct sock *sk, long timeout)
{
	lock_sock(sk);

	quic_set_state(sk, QUIC_SS_CLOSED);

	release_sock(sk);

	sk_common_release(sk);
}

/**
 * quic_do_setsockopt - set a QUIC socket option
 * @sk: socket to configure
 * @optname: option name (QUIC-level)
 * @optval: user buffer containing the option value
 * @optlen: size of the option value
 *
 * Sets a QUIC socket option on a given socket.
 *
 * Return:
 * - On success, 0 is returned.
 * - On error, a negative error value is returned.
 */
int quic_do_setsockopt(struct sock *sk, int optname, sockptr_t optval,
		       unsigned int optlen)
{
	return -EOPNOTSUPP;
}
EXPORT_SYMBOL_GPL(quic_do_setsockopt);

static int quic_setsockopt(struct sock *sk, int level, int optname,
			   sockptr_t optval, unsigned int optlen)
{
	if (level != SOL_QUIC)
		return quic_common_setsockopt(sk, level, optname, optval,
					      optlen);

	return quic_do_setsockopt(sk, optname, optval, optlen);
}

/**
 * quic_do_getsockopt - get a QUIC socket option
 * @sk: socket to query
 * @optname: option name (QUIC-level)
 * @optval: user buffer to receive the option value
 * @optlen: pointer to buffer size; updated with actual size on return
 *
 * Gets a QUIC socket option from a given socket.
 *
 * Return:
 * - On success, 0 is returned.
 * - On error, a negative error value is returned.
 */
int quic_do_getsockopt(struct sock *sk, int optname, sockptr_t optval,
		       sockptr_t optlen)
{
	return -EOPNOTSUPP;
}
EXPORT_SYMBOL_GPL(quic_do_getsockopt);

static int quic_getsockopt(struct sock *sk, int level, int optname,
			   char __user *optval, int __user *optlen)
{
	if (level != SOL_QUIC)
		return quic_common_getsockopt(sk, level, optname, optval,
					      optlen);

	return quic_do_getsockopt(sk, optname, USER_SOCKPTR(optval),
				  USER_SOCKPTR(optlen));
}

static void quic_release_cb(struct sock *sk)
{
}

static int quic_disconnect(struct sock *sk, int flags)
{
	return -EOPNOTSUPP;
}

static void quic_shutdown(struct sock *sk, int how)
{
	quic_set_state(sk, QUIC_SS_CLOSED);
}

static int quic_backlog_rcv(struct sock *sk, struct sk_buff *skb)
{
	kfree_skb(skb);
	return 0;
}

struct proto quic_prot = {
	.name		=  "QUIC",
	.owner		=  THIS_MODULE,
	.init		=  quic_init_sock,
	.destroy	=  quic_destroy_sock,
	.shutdown	=  quic_shutdown,
	.setsockopt	=  quic_setsockopt,
	.getsockopt	=  quic_getsockopt,
	.connect	=  quic_connect,
	.bind		=  quic_bind,
	.close		=  quic_close,
	.disconnect	=  quic_disconnect,
	.sendmsg	=  quic_sendmsg,
	.recvmsg	=  quic_recvmsg,
	.accept		=  quic_accept,
	.hash		=  quic_hash,
	.unhash		=  quic_unhash,
	.backlog_rcv	=  quic_backlog_rcv,
	.release_cb	=  quic_release_cb,
	.no_autobind	=  true,
	.obj_size	=  sizeof(struct quic_sock),
	.sysctl_mem		=  sysctl_quic_mem,
	.sysctl_rmem		=  sysctl_quic_rmem,
	.sysctl_wmem		=  sysctl_quic_wmem,
	.memory_pressure	=  &quic_memory_pressure,
	.enter_memory_pressure	=  quic_enter_memory_pressure,
	.memory_allocated	=  &quic_memory_allocated,
	.per_cpu_fw_alloc	=  &quic_memory_per_cpu_fw_alloc,
	.sockets_allocated	=  &quic_sockets_allocated,
};

struct proto quicv6_prot = {
	.name		=  "QUICv6",
	.owner		=  THIS_MODULE,
	.init		=  quic_init_sock,
	.destroy	=  quic_destroy_sock,
	.shutdown	=  quic_shutdown,
	.setsockopt	=  quic_setsockopt,
	.getsockopt	=  quic_getsockopt,
	.connect	=  quic_connect,
	.bind		=  quic_bind,
	.close		=  quic_close,
	.disconnect	=  quic_disconnect,
	.sendmsg	=  quic_sendmsg,
	.recvmsg	=  quic_recvmsg,
	.accept		=  quic_accept,
	.hash		=  quic_hash,
	.unhash		=  quic_unhash,
	.backlog_rcv	=  quic_backlog_rcv,
	.release_cb	=  quic_release_cb,
	.no_autobind	=  true,
	.obj_size	= sizeof(struct quic6_sock),
	.ipv6_pinfo_offset	=  offsetof(struct quic6_sock, inet6),
	.sysctl_mem		=  sysctl_quic_mem,
	.sysctl_rmem		=  sysctl_quic_rmem,
	.sysctl_wmem		=  sysctl_quic_wmem,
	.memory_pressure	=  &quic_memory_pressure,
	.enter_memory_pressure	=  quic_enter_memory_pressure,
	.memory_allocated	=  &quic_memory_allocated,
	.per_cpu_fw_alloc	=  &quic_memory_per_cpu_fw_alloc,
	.sockets_allocated	=  &quic_sockets_allocated,
};
