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

/* Check if a matching request sock already exists. Match is based on
 * source/destination addresses and DCID.
 */
struct quic_request_sock *quic_request_sock_lookup(struct sock *sk)
{
	struct quic_packet *packet = quic_packet(sk);
	struct quic_request_sock *req;

	list_for_each_entry(req, quic_reqs(sk), list) {
		if (!memcmp(&req->saddr, &packet->saddr, sizeof(req->saddr)) &&
		    !memcmp(&req->daddr, &packet->daddr, sizeof(req->daddr)) &&
		    !quic_conn_id_cmp(&req->dcid, &packet->dcid))
			return req;
	}
	return NULL;
}

/* Create and enqueue a QUIC request sock for a new incoming connection. */
struct quic_request_sock *quic_request_sock_create(struct sock *sk,
						   struct quic_conn_id *odcid,
						   u8 retry, gfp_t gfp)
{
	struct quic_packet *packet = quic_packet(sk);
	struct quic_request_sock *req;

	if (sk_acceptq_is_full(sk)) /* Refuse if accept queue full. */
		return ERR_PTR(-ENOBUFS);

	req = kmalloc_obj(*req, gfp);
	if (!req)
		return ERR_PTR(-ENOMEM);

	req->version = packet->version;
	req->daddr = packet->daddr;
	req->saddr = packet->saddr;
	req->scid = packet->scid;
	req->dcid = packet->dcid;
	req->orig_dcid = *odcid;
	req->retry = retry;

	skb_queue_head_init(&req->backlog_list);
	req->blen = 0;

	/* Enqueue request into listen socket’s pending list for accept(). */
	list_add_tail(&req->list, quic_reqs(sk));
	sk_acceptq_added(sk);
	return req;
}

int quic_request_sock_backlog_tail(struct sock *sk,
				   struct quic_request_sock *req,
				   struct sk_buff *skb)
{
	u32 limit = sk->sk_rcvbuf / sk->sk_max_ack_backlog;
	int len = skb->truesize;

	limit =  max_t(u32, limit, QUIC_MIN_UDP_PAYLOAD * 4);
	if (req->blen + len > limit || !__sk_rmem_schedule(sk, len, false)) {
		QUIC_INC_STATS(sock_net(sk), QUIC_MIB_PKT_RCVDROP);
		kfree_skb(skb);
		return -ENOBUFS;
	}

	QUIC_SKB_CB(skb)->backlog = 1;
	skb_set_owner_r(skb, sk);
	__skb_queue_tail(&req->backlog_list, skb);
	req->blen += len;

	sk->sk_data_ready(sk);
	return 0;
}

/* Check if a matching accept socket exists. This is needed because an accept
 * socket might have been created after this packet was enqueued in the listen
 * socket's backlog.
 */
bool quic_accept_sock_exists(struct sock *sk, struct sk_buff *skb)
{
	struct quic_packet *packet = quic_packet(sk);
	bool exist = false;

	/* Skip if packet is newer than the last accept socket creation time.
	 * No matching socket could exist in this case.
	 */
	if (QUIC_SKB_CB(skb)->time >
	    quic_pnspace(sk, QUIC_CRYPTO_INITIAL)->time)
		return exist;

	/* Look up accepted socket matching packet addresses and DCID. */
	local_bh_disable();
	sk = quic_sock_lookup(skb, &packet->saddr, &packet->daddr,
			      quic_path_usock(quic_paths(sk), 0),
			      &packet->dcid);
	if (!sk)
		goto out;

	/* Found a matching accept socket. Process packet with this socket. */
	skb_orphan(skb);
	bh_lock_sock_nested(sk);
	if (sock_owned_by_user(sk)) {
		/* Socket is busy (owned by user context): queue to backlog. */
		if (sk_add_backlog(sk, skb, READ_ONCE(sk->sk_rcvbuf))) {
			QUIC_INC_STATS(sock_net(sk), QUIC_MIB_PKT_RCVDROP);
			kfree_skb(skb);
		}
	} else {
		/* Socket not busy: process immediately. */
		sk->sk_backlog_rcv(sk, skb); /* quic_packet_process(). */
	}
	bh_unlock_sock(sk);
	sock_put(sk);
	exist = true;
out:
	local_bh_enable();
	return exist;
}

/* Lookup a connected QUIC socket based on address and dest connection ID.
 *
 * This function searches the established (non-listening) QUIC socket table for
 * a socket that matches the source and dest addresses and, optionally, the
 * dest connection ID (DCID). The value returned by quic_path_orig_dcid() might
 * be the original dest connection ID from the ClientHello or the Source
 * Connection ID from a Retry packet before.
 *
 * The DCID is provided from a handshake packet when searching by source
 * connection ID fails, such as when the peer has not yet received server's
 * response and updated the DCID.
 *
 * Return: A pointer to the matching connected socket, or NULL if no match is
 * found.
 */
struct sock *quic_sock_lookup(struct sk_buff *skb, union quic_addr *sa,
			      union quic_addr *da, struct sock *usk,
			      struct quic_conn_id *dcid)
{
	union quic_addr *path_sa, *path_da;
	struct net *net = sock_net(usk);
	struct quic_path_group *paths;
	struct hlist_nulls_node *node;
	struct quic_shash_head *head;
	struct sock *sk = NULL, *tmp;
	struct quic_conn_id *odcid;
	unsigned int hash, seq;
	bool match;

	hash = quic_sock_hash(net, sa, da);
	head = quic_sock_head(hash);

	rcu_read_lock();
begin:
	sk_nulls_for_each_rcu(tmp, node, &head->head) {
		if (net != sock_net(tmp))
			continue;
		paths = quic_paths(tmp);
		odcid = quic_path_orig_dcid(paths);

		/* Protect path[0] reads with seqcount retry to detect torn
		 * reads during concurrent quic_path_swap(). The seqcount
		 * ensures we either see a consistent old or new path, never
		 * a mix of both.
		 */
		do {
			seq = read_seqcount_begin(&paths->path_seq);
			path_sa = quic_path_saddr(paths, 0);
			path_da = quic_path_daddr(paths, 0);
			match = (quic_cmp_sk_addr(tmp, path_sa, sa) &&
				 quic_cmp_sk_addr(tmp, path_da, da) &&
				 quic_path_usock(paths, 0) == usk &&
				 (!dcid || !quic_conn_id_cmp(odcid, dcid)));
		} while (read_seqcount_retry(&paths->path_seq, seq));

		if (match) {
			sk = tmp;
			break;
		}
	}
	/* If the final nulls value differs from the expected one, restart the
	 * lookup as the node may have been rehashed (e.g., due to connection
	 * migration).
	 */
	if (!sk && get_nulls_value(node) != hash)
		goto begin;

	if (sk && unlikely(!refcount_inc_not_zero(&sk->sk_refcnt)))
		sk = NULL;
	rcu_read_unlock();
	return sk;
}

/* Find the listening QUIC socket for an incoming packet.
 *
 * This function searches the QUIC socket table for a listening socket that
 * matches the dest address and port, and the ALPN(s) if presented in the
 * ClientHello.  If multiple listening sockets are bound to the same address,
 * port, and ALPN(s) (e.g., via SO_REUSEPORT), this function selects a socket
 * from the reuseport group.
 *
 * Return: A pointer to the matching listening socket, or NULL if no match is
 * found.
 */
struct sock *quic_listen_sock_lookup(struct sk_buff *skb, union quic_addr *sa,
				     union quic_addr *da, struct sock *usk,
				     struct quic_data *alpns)
{
	struct net *net = sock_net(usk);
	struct hlist_nulls_node *node;
	struct sock *sk = NULL, *tmp;
	struct quic_shash_head *head;
	struct quic_data alpn;
	union quic_addr *a;
	u32 hash, len;
	u64 length;
	u8 *p;

	hash = quic_listen_sock_hash(net, ntohs(sa->v4.sin_port));
	head = quic_listen_sock_head(hash);

	rcu_read_lock();
	/* Iterate sockets, checking ALPN requirements. Address specificity
	 * always takes precedence over ALPN preference order.
	 */
	sk_nulls_for_each_rcu(tmp, node, &head->head) {
		bool alpn_match = false;

		a = quic_path_saddr(quic_paths(tmp), 0);
		if (net != sock_net(tmp) || !quic_cmp_sk_addr(tmp, a, sa) ||
		    quic_path_usock(quic_paths(tmp), 0) != usk)
			continue;

		if (!alpns->len) {
			/* No ALPN extension or empty ALPN list.
			 * If alpns->data is NULL, match any socket.
			 * If alpns->data is set (empty ALPN), only match
			 * sockets with no ALPN configured.
			 */
			alpn_match = (!alpns->data || !quic_alpn(tmp)->len);
		} else {
			/* Check if any client ALPN matches this socket. */
			for (p = alpns->data, len = alpns->len; len;
			     len -= length, p += length) {
				quic_get_int(&p, &len, &length, 1);
				quic_data(&alpn, p, length);
				if (quic_data_has(quic_alpn(tmp), &alpn)) {
					alpn_match = true;
					break;
				}
			}
		}

		if (alpn_match) {
			if (!quic_is_any_addr(a)) {
				/* Specific address - best match. */
				sk = tmp;
				goto out;
			}
			/* ANY address - keep as candidate. */
			if (!sk || a->sa.sa_family == sa->sa.sa_family)
				sk = tmp;
		}
	}
	/* No need to check get_nulls_value(node) != hash for !sk, as
	 * hashtable size is fixed and a listen sk can not rehashed.
	 */
out:
	if (sk && sk->sk_reuseport)
		sk = reuseport_select_sock(sk, quic_addr_hash(net, da), skb, 1);

	if (sk && unlikely(!refcount_inc_not_zero(&sk->sk_refcnt)))
		sk = NULL;
	rcu_read_unlock();
	return sk;
}

/* Switch packet to a different listening socket based on ALPN matching.
 *
 * When ALPN demultiplexing is enabled, this function attempts to find a
 * listening socket that matches the parsed ALPN. If a different socket is
 * found, the packet is switched to that socket for processing.
 *
 * Return: true if switched to a different socket, false otherwise.
 */
bool quic_listen_sock_switch(struct sk_buff *skb, struct quic_data *alpns)
{
	struct sock *nsk, *sk = skb->sk;
	struct quic_packet *packet;

	if (!alpns->data)
		return false;

	local_bh_disable();
	packet = quic_packet(sk);
	nsk = quic_listen_sock_lookup(skb, &packet->saddr, &packet->daddr,
				      quic_path_usock(quic_paths(sk), 0),
				      alpns);
	if (!nsk)
		goto out;
	if (nsk == sk) {
		sock_put(nsk);
		goto out;
	}
	local_bh_enable();
	release_sock(sk);

	skb_orphan(skb);

	lock_sock(nsk);
	nsk->sk_backlog_rcv(nsk, skb); /* quic_packet_process(). */
	release_sock(nsk);
	sock_put(nsk);

	lock_sock(sk);
	return true;
out:
	local_bh_enable();
	return false;
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

	/* Deferred ALPN free for RCU readers in quic_listen_sock_lookup(). */
	quic_data_free(quic_alpn(sk));

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

	quic_timer_init(sk);
	quic_packet_init(sk);

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

	quic_timer_free(sk);
	quic_packet_free(sk);

	for (i = 0; i < QUIC_PNSPACE_MAX; i++)
		quic_pnspace_free(quic_pnspace(sk, i));

	quic_path_unbind(sk, quic_paths(sk), 0);
	quic_path_unbind(sk, quic_paths(sk), 1);

	quic_conn_id_set_free(quic_source(sk));
	quic_conn_id_set_free(quic_dest(sk));

	quic_stream_free(quic_streams(sk));

	quic_data_free(quic_ticket(sk));
	quic_data_free(quic_token(sk));

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
	/* Similar to tcp_release_cb(). */
	unsigned long nflags, flags = smp_load_acquire(&sk->sk_tsq_flags);

	do {
		if (!(flags & QUIC_DEFERRED_ALL))
			return;
		nflags = flags & ~QUIC_DEFERRED_ALL;
	} while (!try_cmpxchg(&sk->sk_tsq_flags, &flags, nflags));

	if (flags & QUIC_F_MTU_REDUCED_DEFERRED) {
		quic_packet_rcv_err_pmtu(sk);
		__sock_put(sk);
	}
	if (flags & QUIC_F_LOSS_DEFERRED) {
		quic_timer_loss_handler(sk);
		__sock_put(sk);
	}
	if (flags & QUIC_F_SACK_DEFERRED) {
		quic_timer_sack_handler(sk);
		__sock_put(sk);
	}
	if (flags & QUIC_F_PATH_DEFERRED) {
		quic_timer_path_handler(sk);
		__sock_put(sk);
	}
	if (flags & QUIC_F_PMTU_DEFERRED) {
		quic_timer_pmtu_handler(sk);
		__sock_put(sk);
	}
	if (flags & QUIC_F_PACE_DEFERRED) {
		quic_timer_pace_handler(sk);
		__sock_put(sk);
	}
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
	return quic_packet_process(sk, skb, GFP_ATOMIC);
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
