// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2017 - 2018 Covalent IO, Inc. http://covalent.io */

#include <linux/skmsg.h>
#include <linux/filter.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/circ_buf.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/wait.h>
#include <linux/util_macros.h>
#include <linux/percpu-refcount.h>

#include <net/busy_poll.h>
#include <net/inet_common.h>
#include <net/inet_sock.h>
#include <net/tls.h>
#include <asm/ioctls.h>

static bool sk_psock_is_spliced(const struct sk_psock *psock);
static int tcp_bpf_splice_recvmsg(struct sock *sk, struct sk_psock *psock,
				  struct msghdr *msg, size_t len,
				  int flags, int *err);
static int splice_send_ring(struct sock *sk, struct sk_psock *psock,
			    struct msghdr *msg, size_t size, int flags);
static int tcp_bpf_splice_sendmsg(struct sock *sk, struct msghdr *msg,
				  size_t size);
static void splice_ring_free(struct sk_psock_splice *s);
static bool tcp_bpf_is_readable(struct sock *sk);

void tcp_eat_skb(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tcp;
	int copied;

	if (!skb || !skb->len || !sk_is_tcp(sk))
		return;

	if (skb_bpf_strparser(skb))
		return;

	tcp = tcp_sk(sk);
	copied = tcp->copied_seq + skb->len;
	WRITE_ONCE(tcp->copied_seq, copied);
	tcp_rcv_space_adjust(sk);
	__tcp_cleanup_rbuf(sk, skb->len);
}

static int bpf_tcp_ingress(struct sock *sk, struct sk_psock *psock,
			   struct sk_msg *msg, u32 apply_bytes)
{
	bool apply = apply_bytes;
	struct scatterlist *sge;
	u32 size, copied = 0;
	struct sk_msg *tmp;
	int i, ret = 0;

	tmp = kzalloc_obj(*tmp, __GFP_NOWARN | GFP_KERNEL);
	if (unlikely(!tmp))
		return -ENOMEM;

	lock_sock(sk);
	tmp->sg.start = msg->sg.start;
	i = msg->sg.start;
	do {
		sge = sk_msg_elem(msg, i);
		size = (apply && apply_bytes < sge->length) ?
			apply_bytes : sge->length;
		if (!__sk_rmem_schedule(sk, size, false)) {
			if (!copied)
				ret = -ENOMEM;
			break;
		}

		sk_mem_charge(sk, size);
		atomic_add(size, &sk->sk_rmem_alloc);
		sk_msg_xfer(tmp, msg, i, size);
		copied += size;
		if (sge->length)
			get_page(sk_msg_page(tmp, i));
		sk_msg_iter_var_next(i);
		tmp->sg.end = i;
		if (apply) {
			apply_bytes -= size;
			if (!apply_bytes) {
				if (sge->length)
					sk_msg_iter_var_prev(i);
				break;
			}
		}
	} while (i != msg->sg.end);

	if (!ret) {
		msg->sg.start = i;
		if (!sk_psock_queue_msg(psock, tmp))
			atomic_sub(copied, &sk->sk_rmem_alloc);
		sk_psock_data_ready(sk, psock);
	} else {
		sk_msg_free(sk, tmp);
		kfree(tmp);
	}

	release_sock(sk);
	return ret;
}

static int tcp_bpf_push(struct sock *sk, struct sk_msg *msg, u32 apply_bytes,
			int flags, bool uncharge)
{
	struct msghdr msghdr = {};
	bool apply = apply_bytes;
	struct scatterlist *sge;
	struct page *page;
	int size, ret = 0;
	u32 off;

	while (1) {
		struct bio_vec bvec;
		bool has_tx_ulp;

		sge = sk_msg_elem(msg, msg->sg.start);
		size = (apply && apply_bytes < sge->length) ?
			apply_bytes : sge->length;
		off  = sge->offset;
		page = sg_page(sge);

		tcp_rate_check_app_limited(sk);
retry:
		msghdr.msg_flags = flags | MSG_SPLICE_PAGES;
		has_tx_ulp = tls_sw_has_ctx_tx(sk);
		if (has_tx_ulp)
			msghdr.msg_flags |= MSG_SENDPAGE_NOPOLICY;

		if (size < sge->length && msg->sg.start != msg->sg.end)
			msghdr.msg_flags |= MSG_MORE;

		bvec_set_page(&bvec, page, size, off);
		iov_iter_bvec(&msghdr.msg_iter, ITER_SOURCE, &bvec, 1, size);
		ret = tcp_sendmsg_locked(sk, &msghdr, size);
		if (ret <= 0)
			return ret;

		if (apply)
			apply_bytes -= ret;
		msg->sg.size -= ret;
		sge->offset += ret;
		sge->length -= ret;
		if (uncharge)
			sk_mem_uncharge(sk, ret);
		if (ret != size) {
			size -= ret;
			off  += ret;
			goto retry;
		}
		if (!sge->length) {
			put_page(page);
			sk_msg_iter_next(msg, start);
			sg_init_table(sge, 1);
			if (msg->sg.start == msg->sg.end)
				break;
		}
		if (apply && !apply_bytes)
			break;
	}

	return 0;
}

static int tcp_bpf_push_locked(struct sock *sk, struct sk_msg *msg,
			       u32 apply_bytes, int flags, bool uncharge)
{
	int ret;

	lock_sock(sk);
	ret = tcp_bpf_push(sk, msg, apply_bytes, flags, uncharge);
	release_sock(sk);
	return ret;
}

int tcp_bpf_sendmsg_redir(struct sock *sk, bool ingress,
			  struct sk_msg *msg, u32 bytes, int flags)
{
	struct sk_psock *psock = sk_psock_get(sk);
	int ret;

	if (unlikely(!psock))
		return -EPIPE;

	ret = ingress ? bpf_tcp_ingress(sk, psock, msg, bytes) :
			tcp_bpf_push_locked(sk, msg, bytes, flags, false);
	sk_psock_put(sk, psock);
	return ret;
}
EXPORT_SYMBOL_GPL(tcp_bpf_sendmsg_redir);

#ifdef CONFIG_BPF_SYSCALL
static int tcp_msg_wait_data(struct sock *sk, struct sk_psock *psock,
			     long timeo)
{
	DEFINE_WAIT_FUNC(wait, woken_wake_function);
	int ret = 0;

	if (sk->sk_shutdown & RCV_SHUTDOWN)
		return 1;

	if (!timeo)
		return ret;

	add_wait_queue(sk_sleep(sk), &wait);
	sk_set_bit(SOCKWQ_ASYNC_WAITDATA, sk);
	ret = sk_wait_event(sk, &timeo,
			    !list_empty(&psock->ingress_msg) ||
			    !skb_queue_empty_lockless(&sk->sk_receive_queue), &wait);
	sk_clear_bit(SOCKWQ_ASYNC_WAITDATA, sk);
	remove_wait_queue(sk_sleep(sk), &wait);
	return ret;
}

static bool is_next_msg_fin(struct sk_psock *psock)
{
	struct scatterlist *sge;
	struct sk_msg *msg_rx;
	int i;

	msg_rx = sk_psock_peek_msg(psock);
	i = msg_rx->sg.start;
	sge = sk_msg_elem(msg_rx, i);
	if (!sge->length) {
		struct sk_buff *skb = msg_rx->skb;

		if (skb && TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN)
			return true;
	}
	return false;
}

static int tcp_bpf_recvmsg_parser(struct sock *sk,
				  struct msghdr *msg,
				  size_t len,
				  int flags)
{
	int peek = flags & MSG_PEEK;
	struct sk_psock *psock;
	struct tcp_sock *tcp;
	int copied_from_self = 0;
	int copied = 0;
	u32 seq;

	if (unlikely(flags & MSG_ERRQUEUE))
		return inet_recv_error(sk, msg, len);

	if (!len)
		return 0;

	psock = sk_psock_get(sk);
	if (unlikely(!psock))
		return tcp_recvmsg(sk, msg, len, flags);

	lock_sock(sk);
	tcp = tcp_sk(sk);
	seq = tcp->copied_seq;
	/* We may have received data on the sk_receive_queue pre-accept and
	 * then we can not use read_skb in this context because we haven't
	 * assigned a sk_socket yet so have no link to the ops. The work-around
	 * is to check the sk_receive_queue and in these cases read skbs off
	 * queue again. The read_skb hook is not running at this point because
	 * of lock_sock so we avoid having multiple runners in read_skb.
	 */
	if (unlikely(!skb_queue_empty(&sk->sk_receive_queue))) {
		tcp_data_ready(sk);
		/* This handles the ENOMEM errors if we both receive data
		 * pre accept and are already under memory pressure. At least
		 * let user know to retry.
		 */
		if (unlikely(!skb_queue_empty(&sk->sk_receive_queue))) {
			copied = -EAGAIN;
			goto out;
		}
	}

msg_bytes_ready:
	copied = __sk_msg_recvmsg(sk, psock, msg, len, flags, &copied_from_self);
	/* The typical case for EFAULT is the socket was gracefully
	 * shutdown with a FIN pkt. So check here the other case is
	 * some error on copy_page_to_iter which would be unexpected.
	 * On fin return correct return code to zero.
	 */
	if (copied == -EFAULT) {
		bool is_fin = is_next_msg_fin(psock);

		if (is_fin) {
			copied = 0;
			seq++;
			goto out;
		}
	}
	seq += copied_from_self;
	if (!copied) {
		long timeo;
		int data;

		if (sock_flag(sk, SOCK_DONE))
			goto out;

		if (sk->sk_err) {
			copied = sock_error(sk);
			goto out;
		}

		if (sk->sk_shutdown & RCV_SHUTDOWN)
			goto out;

		if (sk->sk_state == TCP_CLOSE) {
			copied = -ENOTCONN;
			goto out;
		}

		timeo = sock_rcvtimeo(sk, flags & MSG_DONTWAIT);
		if (!timeo) {
			copied = -EAGAIN;
			goto out;
		}

		if (signal_pending(current)) {
			copied = sock_intr_errno(timeo);
			goto out;
		}

		data = tcp_msg_wait_data(sk, psock, timeo);
		if (data < 0) {
			copied = data;
			goto unlock;
		}
		if (data && !sk_psock_queue_empty(psock))
			goto msg_bytes_ready;
		copied = -EAGAIN;
	}
out:
	if (!peek)
		WRITE_ONCE(tcp->copied_seq, seq);
	tcp_rcv_space_adjust(sk);
	if (copied > 0)
		__tcp_cleanup_rbuf(sk, copied);

unlock:
	release_sock(sk);
	sk_psock_put(sk, psock);
	return copied;
}

static int tcp_bpf_ioctl(struct sock *sk, int cmd, int *karg)
{
	bool slow;

	if (cmd != SIOCINQ)
		return tcp_ioctl(sk, cmd, karg);

	/* works similar as tcp_ioctl */
	if (sk->sk_state == TCP_LISTEN)
		return -EINVAL;

	slow = lock_sock_fast(sk);
	*karg = sk_psock_msg_inq(sk);
	unlock_sock_fast(sk, slow);

	return 0;
}

static int tcp_bpf_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
			   int flags)
{
	struct sk_psock *psock;
	int copied, ret;

	if (unlikely(flags & MSG_ERRQUEUE))
		return inet_recv_error(sk, msg, len);

	if (!len)
		return 0;

	psock = sk_psock_get(sk);
	if (unlikely(!psock))
		return tcp_recvmsg(sk, msg, len, flags);

	/* Splice dispatch.
	 *
	 * Streaming-friendly ordering: drain anything TCP has already
	 * queued in sk_receive_queue FIRST. The sender stays on plain
	 * tcp_sendmsg() (preserving Nagle, TSO, sk_write_queue
	 * coalescing) whenever the peer rcv_queue has bytes in flight,
	 * so if a receiver is keeping up with a bulk stream we never
	 * publish a bvec and never push the sender into per-message
	 * synchronous mode. Only when sk_receive_queue is empty (the
	 * receiver would otherwise block) do we enter the rendezvous
	 * path; the sender's opportunistic check then finds our pinned
	 * iov and does the direct user-to-user copy fast path.
	 *
	 * splice_recvmsg returns 0 with no error if rcv_queue gained
	 * bytes during the wait (TCP arrival raced our pin), in which
	 * case the next block below drains them via tcp_recvmsg() and
	 * stream ordering is preserved end-to-end.
	 */
	if (sk_psock_is_spliced(psock)) {
		int err = 0, rcopied;

		/* tcp_bpf_splice_recvmsg drains the ring first (ring bytes
		 * predate any rcv_queue bytes when both have data) and only
		 * returns 0 when both are empty or rcv_queue has the only
		 * bytes left. The block below then routes the rcv_queue
		 * drain via tcp_recvmsg().
		 */
		rcopied = tcp_bpf_splice_recvmsg(sk, psock, msg, len,
						 flags, &err);
		if (rcopied > 0) {
			sk_psock_put(sk, psock);
			return rcopied;
		}
		if (err) {
			sk_psock_put(sk, psock);
			return err;
		}
	}

	if (!skb_queue_empty(&sk->sk_receive_queue) &&
	    sk_psock_queue_empty(psock)) {
		sk_psock_put(sk, psock);
		return tcp_recvmsg(sk, msg, len, flags);
	}
	lock_sock(sk);
msg_bytes_ready:
	copied = sk_msg_recvmsg(sk, psock, msg, len, flags);
	if (!copied) {
		long timeo;
		int data;

		timeo = sock_rcvtimeo(sk, flags & MSG_DONTWAIT);
		data = tcp_msg_wait_data(sk, psock, timeo);
		if (data < 0) {
			ret = data;
			goto unlock;
		}
		if (data) {
			if (!sk_psock_queue_empty(psock))
				goto msg_bytes_ready;
			release_sock(sk);
			sk_psock_put(sk, psock);
			return tcp_recvmsg(sk, msg, len, flags);
		}
		copied = -EAGAIN;
	}
	ret = copied;

unlock:
	release_sock(sk);
	sk_psock_put(sk, psock);
	return ret;
}

static int tcp_bpf_send_verdict(struct sock *sk, struct sk_psock *psock,
				struct sk_msg *msg, int *copied, int flags)
{
	bool cork = false, enospc = sk_msg_full(msg), redir_ingress;
	struct sock *sk_redir;
	u32 tosend, origsize, sent, delta = 0;
	u32 eval;
	int ret;

more_data:
	if (psock->eval == __SK_NONE) {
		/* Track delta in msg size to add/subtract it on SK_DROP from
		 * returned to user copied size. This ensures user doesn't
		 * get a positive return code with msg_cut_data and SK_DROP
		 * verdict.
		 */
		delta = msg->sg.size;
		psock->eval = sk_psock_msg_verdict(sk, psock, msg);
		delta -= msg->sg.size;
	}

	if (msg->cork_bytes &&
	    msg->cork_bytes > msg->sg.size && !enospc) {
		psock->cork_bytes = msg->cork_bytes - msg->sg.size;
		if (!psock->cork) {
			psock->cork = kzalloc_obj(*psock->cork,
						  GFP_ATOMIC | __GFP_NOWARN);
			if (!psock->cork) {
				sk_msg_free(sk, msg);
				*copied = 0;
				return -ENOMEM;
			}
		}
		memcpy(psock->cork, msg, sizeof(*msg));
		return 0;
	}

	tosend = msg->sg.size;
	if (psock->apply_bytes && psock->apply_bytes < tosend)
		tosend = psock->apply_bytes;
	eval = __SK_NONE;

	switch (psock->eval) {
	case __SK_PASS:
		ret = tcp_bpf_push(sk, msg, tosend, flags, true);
		if (unlikely(ret)) {
			*copied -= sk_msg_free(sk, msg);
			break;
		}
		sk_msg_apply_bytes(psock, tosend);
		break;
	case __SK_REDIRECT:
		redir_ingress = psock->redir_ingress;
		sk_redir = psock->sk_redir;
		sk_msg_apply_bytes(psock, tosend);
		if (!psock->apply_bytes) {
			/* Clean up before releasing the sock lock. */
			eval = psock->eval;
			psock->eval = __SK_NONE;
			psock->sk_redir = NULL;
		}
		if (psock->cork) {
			cork = true;
			psock->cork = NULL;
		}
		release_sock(sk);

		origsize = msg->sg.size;
		ret = tcp_bpf_sendmsg_redir(sk_redir, redir_ingress,
					    msg, tosend, flags);
		sent = origsize - msg->sg.size;

		if (eval == __SK_REDIRECT)
			sock_put(sk_redir);

		lock_sock(sk);
		sk_mem_uncharge(sk, sent);
		if (unlikely(ret < 0)) {
			int free = sk_msg_free(sk, msg);

			if (!cork)
				*copied -= free;
		}
		if (cork) {
			sk_msg_free(sk, msg);
			kfree(msg);
			msg = NULL;
			ret = 0;
		}
		break;
	case __SK_DROP:
	default:
		sk_msg_free(sk, msg);
		sk_msg_apply_bytes(psock, tosend);
		*copied -= (tosend + delta);
		return -EACCES;
	}

	if (likely(!ret)) {
		if (!psock->apply_bytes) {
			psock->eval =  __SK_NONE;
			if (psock->sk_redir) {
				sock_put(psock->sk_redir);
				psock->sk_redir = NULL;
			}
		}
		if (msg &&
		    msg->sg.data[msg->sg.start].page_link &&
		    msg->sg.data[msg->sg.start].length)
			goto more_data;
	}
	return ret;
}

static int tcp_bpf_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
{
	struct sk_msg tmp, *msg_tx = NULL;
	int copied = 0, err = 0, ret = 0;
	struct sk_psock *psock;
	long timeo;
	int flags;

	/* Don't let internal flags through */
	flags = (msg->msg_flags & ~MSG_SENDPAGE_DECRYPTED);
	flags |= MSG_NO_SHARED_FRAGS;

	psock = sk_psock_get(sk);
	if (unlikely(!psock))
		return tcp_sendmsg(sk, msg, size);

	lock_sock(sk);
	timeo = sock_sndtimeo(sk, msg->msg_flags & MSG_DONTWAIT);
	while (msg_data_left(msg)) {
		bool enospc = false;
		u32 copy, osize;

		if (sk->sk_err) {
			err = -sk->sk_err;
			goto out_err;
		}

		copy = msg_data_left(msg);
		if (!sk_stream_memory_free(sk))
			goto wait_for_sndbuf;
		if (psock->cork) {
			msg_tx = psock->cork;
		} else {
			msg_tx = &tmp;
			sk_msg_init(msg_tx);
		}

		osize = msg_tx->sg.size;
		err = sk_msg_alloc(sk, msg_tx, msg_tx->sg.size + copy, msg_tx->sg.end - 1);
		if (err) {
			if (err != -ENOSPC)
				goto wait_for_memory;
			enospc = true;
			copy = msg_tx->sg.size - osize;
		}

		ret = sk_msg_memcopy_from_iter(sk, &msg->msg_iter, msg_tx,
					       copy);
		if (ret < 0) {
			sk_msg_trim(sk, msg_tx, osize);
			goto out_err;
		}

		copied += ret;
		if (psock->cork_bytes) {
			if (size > psock->cork_bytes)
				psock->cork_bytes = 0;
			else
				psock->cork_bytes -= size;
			if (psock->cork_bytes && !enospc)
				goto out_err;
			/* All cork bytes are accounted, rerun the prog. */
			psock->eval = __SK_NONE;
			psock->cork_bytes = 0;
		}

		err = tcp_bpf_send_verdict(sk, psock, msg_tx, &copied, flags);
		if (unlikely(err < 0))
			goto out_err;
		continue;
wait_for_sndbuf:
		set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
wait_for_memory:
		err = sk_stream_wait_memory(sk, &timeo);
		if (err) {
			if (msg_tx && msg_tx != psock->cork)
				sk_msg_free(sk, msg_tx);
			goto out_err;
		}
	}
out_err:
	if (err < 0)
		err = sk_stream_error(sk, msg->msg_flags, err);
	release_sock(sk);
	sk_psock_put(sk, psock);
	return copied > 0 ? copied : err;
}

enum {
	TCP_BPF_IPV4,
	TCP_BPF_IPV6,
	TCP_BPF_NUM_PROTS,
};

enum {
	TCP_BPF_BASE,
	TCP_BPF_TX,
	TCP_BPF_RX,
	TCP_BPF_TXRX,
	TCP_BPF_NUM_CFGS,
};

static struct proto *tcpv6_prot_saved __read_mostly;
static DEFINE_SPINLOCK(tcpv6_prot_lock);
static struct proto tcp_bpf_prots[TCP_BPF_NUM_PROTS][TCP_BPF_NUM_CFGS];

static void tcp_bpf_rebuild_protos(struct proto prot[TCP_BPF_NUM_CFGS],
				   struct proto *base)
{
	prot[TCP_BPF_BASE]			= *base;
	prot[TCP_BPF_BASE].destroy		= sock_map_destroy;
	prot[TCP_BPF_BASE].close		= sock_map_close;
	prot[TCP_BPF_BASE].sendmsg		= tcp_bpf_splice_sendmsg;
	prot[TCP_BPF_BASE].recvmsg		= tcp_bpf_recvmsg;
	prot[TCP_BPF_BASE].sock_is_readable	= tcp_bpf_is_readable;
	prot[TCP_BPF_BASE].ioctl		= tcp_bpf_ioctl;

	prot[TCP_BPF_TX]			= prot[TCP_BPF_BASE];
	prot[TCP_BPF_TX].sendmsg		= tcp_bpf_sendmsg;

	prot[TCP_BPF_RX]			= prot[TCP_BPF_BASE];
	prot[TCP_BPF_RX].recvmsg		= tcp_bpf_recvmsg_parser;

	prot[TCP_BPF_TXRX]			= prot[TCP_BPF_TX];
	prot[TCP_BPF_TXRX].recvmsg		= tcp_bpf_recvmsg_parser;
}

static void tcp_bpf_check_v6_needs_rebuild(struct proto *ops)
{
	if (unlikely(ops != smp_load_acquire(&tcpv6_prot_saved))) {
		spin_lock_bh(&tcpv6_prot_lock);
		if (likely(ops != tcpv6_prot_saved)) {
			tcp_bpf_rebuild_protos(tcp_bpf_prots[TCP_BPF_IPV6], ops);
			smp_store_release(&tcpv6_prot_saved, ops);
		}
		spin_unlock_bh(&tcpv6_prot_lock);
	}
}

static int __init tcp_bpf_v4_build_proto(void)
{
	tcp_bpf_rebuild_protos(tcp_bpf_prots[TCP_BPF_IPV4], &tcp_prot);
	return 0;
}
late_initcall(tcp_bpf_v4_build_proto);

static int tcp_bpf_assert_proto_ops(struct proto *ops)
{
	/* In order to avoid retpoline, we make assumptions when we call
	 * into ops if e.g. a psock is not present. Make sure they are
	 * indeed valid assumptions.
	 */
	return ops->recvmsg  == tcp_recvmsg &&
	       ops->sendmsg  == tcp_sendmsg ? 0 : -ENOTSUPP;
}

#if IS_ENABLED(CONFIG_BPF_STREAM_PARSER)
int tcp_bpf_strp_read_sock(struct strparser *strp, read_descriptor_t *desc,
			   sk_read_actor_t recv_actor)
{
	struct sock *sk = strp->sk;
	struct sk_psock *psock;
	struct tcp_sock *tp;
	int copied = 0;

	tp = tcp_sk(sk);
	rcu_read_lock();
	psock = sk_psock(sk);
	if (WARN_ON_ONCE(!psock)) {
		desc->error = -EINVAL;
		goto out;
	}

	psock->ingress_bytes = 0;
	copied = tcp_read_sock_noack(sk, desc, recv_actor, true,
				     &psock->copied_seq);
	if (copied < 0)
		goto out;
	/* recv_actor may redirect skb to another socket (SK_REDIRECT) or
	 * just put skb into ingress queue of current socket (SK_PASS).
	 * For SK_REDIRECT, we need to ack the frame immediately but for
	 * SK_PASS, we want to delay the ack until tcp_bpf_recvmsg_parser().
	 */
	tp->copied_seq = psock->copied_seq - psock->ingress_bytes;
	tcp_rcv_space_adjust(sk);
	__tcp_cleanup_rbuf(sk, copied - psock->ingress_bytes);
out:
	rcu_read_unlock();
	return copied;
}
#endif /* CONFIG_BPF_STREAM_PARSER */

int tcp_bpf_update_proto(struct sock *sk, struct sk_psock *psock, bool restore)
{
	int family = sk->sk_family == AF_INET6 ? TCP_BPF_IPV6 : TCP_BPF_IPV4;
	int config = psock->progs.msg_parser   ? TCP_BPF_TX   : TCP_BPF_BASE;

	if (psock->progs.stream_verdict || psock->progs.skb_verdict) {
		config = (config == TCP_BPF_TX) ? TCP_BPF_TXRX : TCP_BPF_RX;
	}

	if (restore) {
		if (inet_csk_has_ulp(sk)) {
			/* TLS does not have an unhash proto in SW cases,
			 * but we need to ensure we stop using the sock_map
			 * unhash routine because the associated psock is being
			 * removed. So use the original unhash handler.
			 */
			WRITE_ONCE(sk->sk_prot->unhash, psock->saved_unhash);
			tcp_update_ulp(sk, psock->sk_proto, psock->saved_write_space);
		} else {
			WRITE_ONCE(sk->sk_write_space, psock->saved_write_space);
			/* Pairs with lockless read in sk_clone_lock() */
			sock_replace_proto(sk, psock->sk_proto);
		}
		return 0;
	}

	if (sk->sk_family == AF_INET6) {
		if (tcp_bpf_assert_proto_ops(psock->sk_proto))
			return -EINVAL;

		tcp_bpf_check_v6_needs_rebuild(psock->sk_proto);
	}

	/* Pairs with lockless read in sk_clone_lock() */
	sock_replace_proto(sk, &tcp_bpf_prots[family][config]);
	return 0;
}
EXPORT_SYMBOL_GPL(tcp_bpf_update_proto);

/* If a child got cloned from a listening socket that had tcp_bpf
 * protocol callbacks installed, we need to restore the callbacks to
 * the default ones because the child does not inherit the psock state
 * that tcp_bpf callbacks expect.
 */
void tcp_bpf_clone(const struct sock *sk, struct sock *newsk)
{
	struct proto *prot = newsk->sk_prot;

	if (is_insidevar(prot, tcp_bpf_prots))
		newsk->sk_prot = sk->sk_prot_creator;
}

/* Per-psock splice state: a SPSC byte ring (this socket reads from
 * ring_buf; the paired sender writes into it). Sender defers to
 * tcp_sendmsg() when peer rcv_queue is non-empty (ordering) or the
 * ring is full (backpressure); receiver defers to tcp_recvmsg() when
 * rcv_queue has data. Head/tail are monotonic; buffer offset is
 * (cursor & (ring_size - 1)). Data path is lockless via release/
 * acquire on head/tail; ->lock serialises only lazy alloc / teardown.
 */
struct sk_psock_splice {
	struct sk_psock		*peer;      /* NULL after unpair */
	spinlock_t		lock;       /* alloc/teardown only */
	void			*ring_buf;  /* order-2 pages, ring_size bytes */
	size_t			ring_size;  /* power of 2 */
	struct percpu_ref	ring_ref;   /* cross-socket writers into ring_buf */

	/* Producer and consumer cursors live on separate cache lines: the
	 * writer's release-store of ring_head must not invalidate the
	 * reader's hot ring_tail line, and vice versa. cached_tail is the
	 * producer's private cache of ring_tail, kept on the producer's own
	 * line, so the producer reads the consumer-owned ring_tail only when
	 * its cache says the ring is full - standard SPSC cursor caching.
	 */
	unsigned long		ring_head ____cacheline_aligned_in_smp;
	unsigned long		cached_tail;
	unsigned long		ring_tail ____cacheline_aligned_in_smp;
};

#define SPLICE_RING_SIZE	(16U * 1024U)

/* Wake any waiters parked on @sk. Used at teardown so a sleeping
 * receiver observes the cleared ->peer and exits. The smp_mb() closes
 * the same lost-wakeup window as splice_wake_sync() below.
 */
static inline void splice_wake(struct sock *sk)
{
	wait_queue_head_t *wq = sk_sleep(sk);

	smp_mb();
	if (wq && waitqueue_active(wq))
		wake_up_interruptible_all(wq);
}

/* Wake the receiver after a producer write to the ring. The _poll
 * variant with EPOLLIN | EPOLLRDNORM is required so poll()/select()/
 * epoll waiters see the wake (a plain sync wake carries no mask and is
 * silently dropped by poll waiters); wait_event-style waiters wake on
 * it too. The smp_mb() orders the ring head publish before the
 * waitqueue_active() check, pairing with set_current_state() in the
 * consumer's wait loop - without it the producer can skip the wake
 * while the consumer concurrently parks with the predicate just-
 * not-yet-true, a lost wakeup. _sync hints the scheduler to keep the
 * wakee on the producer's CPU.
 */
static inline void splice_wake_sync(struct sock *sk)
{
	wait_queue_head_t *wq = sk_sleep(sk);

	smp_mb();
	if (wq && waitqueue_active(wq))
		wake_up_interruptible_sync_poll(wq, EPOLLIN | EPOLLRDNORM);
}

static bool sk_psock_is_spliced(const struct sk_psock *psock)
{
	struct sk_psock_splice *s = rcu_dereference(psock->splice);

	return s && rcu_access_pointer(s->peer);
}

static int tcp_bpf_splice_sendmsg(struct sock *sk, struct msghdr *msg,
				  size_t size)
{
	struct sk_psock *psock;
	int spliced = 0;
	int ret;

	psock = sk_psock_get(sk);
	if (psock) {
		if (sk_psock_is_spliced(psock)) {
			int flags = (msg->msg_flags &
				     ~MSG_SENDPAGE_DECRYPTED) |
				     MSG_NO_SHARED_FRAGS;

			spliced = splice_send_ring(sk, psock, msg,
						   size, flags);
		}
		sk_psock_put(sk, psock);
	}

	if ((size_t)spliced < size) {
		ret = tcp_sendmsg(sk, msg, size - spliced);
		if (ret < 0)
			return spliced > 0 ? spliced : ret;
		return spliced + ret;
	}
	return spliced;
}

/* percpu_ref release: fires after percpu_ref_kill() once every in-flight
 * cross-socket sender has dropped its hold. Safe to free the ring and the
 * splice state now.
 */
static void splice_ring_ref_release(struct percpu_ref *ref)
{
	struct sk_psock_splice *s =
		container_of(ref, struct sk_psock_splice, ring_ref);

	splice_ring_free(s);
	percpu_ref_exit(&s->ring_ref);
	kfree(s);
}

static struct sk_psock_splice *splice_get_or_alloc(struct sk_psock *psock)
{
	struct sk_psock_splice *s, *old;

	s = rcu_dereference_protected(psock->splice, 1);
	if (s)
		return s;

	s = kzalloc_obj(*s, GFP_ATOMIC);
	if (!s)
		return NULL;
	spin_lock_init(&s->lock);

	if (percpu_ref_init(&s->ring_ref, splice_ring_ref_release, 0,
			    GFP_ATOMIC)) {
		kfree(s);
		return NULL;
	}

	old = cmpxchg((struct sk_psock_splice **)&psock->splice, NULL, s);
	if (old) {
		percpu_ref_exit(&s->ring_ref);
		kfree(s);
		return old;
	}
	return s;
}

static void splice_lock_pair(struct sk_psock_splice *a,
			     struct sk_psock_splice *b)
{
	if (a < b) {
		spin_lock_bh(&a->lock);
		spin_lock_nested(&b->lock, SINGLE_DEPTH_NESTING);
	} else {
		spin_lock_bh(&b->lock);
		spin_lock_nested(&a->lock, SINGLE_DEPTH_NESTING);
	}
}

static void splice_unlock_pair(struct sk_psock_splice *a,
			       struct sk_psock_splice *b)
{
	if (a < b) {
		spin_unlock(&b->lock);
		spin_unlock_bh(&a->lock);
	} else {
		spin_unlock(&a->lock);
		spin_unlock_bh(&b->lock);
	}
}

/*
 * Tear down a splice pair. Idempotent and safe to call from any teardown
 * path (sk_psock_drop, tcp_close, tcp_disconnect, RST handler). No-op if
 * the psock was never spliced.
 *
 * Note: the splice_state allocation is NOT freed here - it lives until
 * sk_psock_destroy. That keeps sender/receiver fast paths free of
 * lifetime dances.
 */
void tcp_bpf_splice_unpair(struct sk_psock *psock)
{
	struct sk_psock_splice *self_s, *peer_s;
	struct sk_psock *peer;
	bool was_paired = false;

	self_s = rcu_dereference_protected(psock->splice, 1);
	if (!self_s)
		return;

	rcu_read_lock();
	peer = rcu_dereference(self_s->peer);
	if (!peer) {
		rcu_read_unlock();
		return;
	}
	if (!sk_psock_get(peer->sk)) {
		rcu_read_unlock();
		return;
	}
	rcu_read_unlock();

	peer_s = rcu_dereference_protected(peer->splice, 1);
	if (!peer_s) {
		sk_psock_put(peer->sk, peer);
		return;
	}

	splice_lock_pair(self_s, peer_s);
	if (self_s->peer == peer && peer_s->peer == psock) {
		rcu_assign_pointer(self_s->peer, NULL);
		rcu_assign_pointer(peer_s->peer, NULL);
		was_paired = true;
	}
	splice_unlock_pair(self_s, peer_s);

	/* Wake any blocked rendezvous waiters on either side. They will
	 * re-check the predicate, see splice->peer == NULL, and exit.
	 */
	splice_wake(psock->sk);
	splice_wake(peer->sk);

	if (was_paired) {
		/* Drop the pair's psock references. Ring buffers are NOT
		 * freed here: a recvmsg may be mid-splice_ring_read() on
		 * either side, holding only sk_psock_get() - it does not
		 * keep ring_buf alive. Defer the kvfree to
		 * tcp_bpf_splice_destroy(), which runs after psock teardown
		 * has drained all callers.
		 */
		sk_psock_put(peer->sk, peer);
		sk_psock_put(psock->sk, psock);
	}
	sk_psock_put(peer->sk, peer);
}
EXPORT_SYMBOL_GPL(tcp_bpf_splice_unpair);

void tcp_bpf_splice_destroy(struct sk_psock *psock)
{
	struct sk_psock_splice *s;

	/* Kill the ring ref; splice_ring_ref_release() frees the ring and s
	 * once any in-flight cross-socket sender has dropped its hold.
	 */
	s = rcu_dereference_protected(psock->splice, 1);
	if (s)
		percpu_ref_kill(&s->ring_ref);
}
EXPORT_SYMBOL_GPL(tcp_bpf_splice_destroy);

/* The PASSIVE_ESTABLISHED_CB fires BEFORE the kernel transitions the
 * accepted child's state from TCP_SYN_RECV to TCP_ESTABLISHED.Accept
 * SYN_RECV here since we know the callback contract guarantees
 * imminent ESTABLISHED.
 */
static bool splice_state_ok(int state)
{
	return state == TCP_ESTABLISHED || state == TCP_SYN_RECV;
}

static int splice_validate(struct sock *a, struct sock *b)
{
	struct tcp_sock *ta = tcp_sk(a), *tb = tcp_sk(b);

	if (a->sk_family != b->sk_family)
		return -EINVAL;
	if (a->sk_protocol != IPPROTO_TCP || b->sk_protocol != IPPROTO_TCP)
		return -EINVAL;
	if (!splice_state_ok(a->sk_state) || !splice_state_ok(b->sk_state))
		return -EINVAL;
	if (ta->repair || tb->repair)
		return -EINVAL;
	if (ta->urg_data || tb->urg_data)
		return -EINVAL;
	return 0;
}

static int splice_ring_alloc(struct sk_psock_splice *s)
{
	void *buf;

	if (READ_ONCE(s->ring_buf))
		return 0;

	buf = (void *)__get_free_pages(GFP_ATOMIC | __GFP_NOWARN,
				       get_order(SPLICE_RING_SIZE));
	if (!buf)
		return -ENOMEM;

	spin_lock_bh(&s->lock);
	if (s->ring_buf) {
		spin_unlock_bh(&s->lock);
		free_pages((unsigned long)buf, get_order(SPLICE_RING_SIZE));
		return 0;
	}
	s->ring_buf    = buf;
	s->ring_size   = SPLICE_RING_SIZE;
	s->ring_head   = 0;
	s->ring_tail   = 0;
	s->cached_tail = 0;
	spin_unlock_bh(&s->lock);
	return 0;
}

static void splice_ring_free(struct sk_psock_splice *s)
{
	void *buf;

	spin_lock_bh(&s->lock);
	buf = s->ring_buf;
	s->ring_buf    = NULL;
	s->ring_size   = 0;
	s->ring_head   = 0;
	s->ring_tail   = 0;
	s->cached_tail = 0;
	spin_unlock_bh(&s->lock);

	if (buf)
		free_pages((unsigned long)buf, get_order(SPLICE_RING_SIZE));
}

static size_t splice_ring_write(struct sk_psock_splice *s,
				struct iov_iter *from, size_t size)
{
	unsigned long head, tail, mask;
	size_t avail, want, to_end, first, second, done;

	if (!s->ring_buf)
		return 0;

	mask = s->ring_size - 1;
	head = s->ring_head;
	/* Use the producer's cached_tail, refreshed by splice_ring_space()
	 * earlier in this same send. It is conservative - the real ring_tail
	 * only advances - so the free space computed here never exceeds the
	 * true free space, and we avoid a second cross-CPU ring_tail read.
	 */
	tail = s->cached_tail;
	avail = CIRC_SPACE(head, tail, s->ring_size);
	want = min_t(size_t, size, avail);
	if (!want)
		return 0;

	to_end = s->ring_size - (head & mask);
	first  = min_t(size_t, want, to_end);

	done = copy_from_iter(s->ring_buf + (head & mask), first, from);
	if (done < first) {
		/* Publish data before head advance. */
		smp_store_release(&s->ring_head, head + done);
		return done;
	}
	second = want - first;
	if (second) {
		done = copy_from_iter(s->ring_buf, second, from);
		/* Publish data before head advance. */
		smp_store_release(&s->ring_head, head + first + done);
		return first + done;
	}
	/* Publish data before head advance. */
	smp_store_release(&s->ring_head, head + first);
	return first;
}

static size_t splice_ring_space(struct sk_psock_splice *s)
{
	unsigned long head = s->ring_head;
	size_t space = CIRC_SPACE(head, s->cached_tail, s->ring_size);

	if (space)
		return space;
	/* Cache exhausted; refresh from the consumer-owned cursor - the only
	 * cross-CPU ring_tail read. Pairs with smp_store_release(&ring_tail).
	 */
	s->cached_tail = smp_load_acquire(&s->ring_tail);
	return CIRC_SPACE(head, s->cached_tail, s->ring_size);
}

static size_t splice_ring_read(struct sk_psock_splice *s,
			       struct iov_iter *to, size_t size)
{
	unsigned long head, tail, mask;
	size_t have, want, to_end, first, second, done;

	if (!s->ring_buf)
		return 0;

	mask = s->ring_size - 1;
	tail = s->ring_tail;
	/* Pairs with smp_store_release(&ring_head) in splice_ring_write():
	 * ensure we read producer's data after observing the head advance.
	 */
	head = smp_load_acquire(&s->ring_head);
	have = CIRC_CNT(head, tail, s->ring_size);
	want = min_t(size_t, size, have);
	if (!want)
		return 0;

	to_end = s->ring_size - (tail & mask);
	first  = min_t(size_t, want, to_end);

	done = copy_to_iter(s->ring_buf + (tail & mask), first, to);
	if (done < first) {
		/* Release: free slots before the producer sees the advance. */
		smp_store_release(&s->ring_tail, tail + done);
		return done;
	}
	second = want - first;
	if (second) {
		done = copy_to_iter(s->ring_buf, second, to);
		/* Release: free slots before the producer sees the advance. */
		smp_store_release(&s->ring_tail, tail + first + done);
		return first + done;
	}
	/* Release: free slots before the producer sees the advance. */
	smp_store_release(&s->ring_tail, tail + first);
	return first;
}

static bool splice_ring_has_data(const struct sk_psock_splice *s)
{
	if (!s->ring_buf)
		return false;
	/* Acquire ring_head so any data published by the producer is
	 * visible if we go on to read it after this check.
	 */
	return CIRC_CNT(smp_load_acquire(&s->ring_head),
			READ_ONCE(s->ring_tail),
			s->ring_size) > 0;
}

static bool splice_recv_ready(struct sock *sk, struct sk_psock_splice *s)
{
	return splice_ring_has_data(s) ||
	       !skb_queue_empty(&sk->sk_receive_queue) ||
	       READ_ONCE(sk->sk_err) ||
	       (READ_ONCE(sk->sk_shutdown) & RCV_SHUTDOWN) ||
	       !rcu_access_pointer(s->peer);
}

static long splice_recv_wait(struct sock *sk, struct sk_psock_splice *s,
			     long timeo)
{
	return wait_event_interruptible_timeout(*sk_sleep(sk),
					splice_recv_ready(sk, s), timeo);
}

/* Bounded busy-poll on the ring before parking the receiver. Reuses the
 * socket's SO_BUSY_POLL budget (sk_ll_usec) via sk_can_busy_loop() and
 * sk_busy_loop_timeout(); the default budget of 0 makes sk_can_busy_loop()
 * false so this is a no-op unless the application (or net.core.busy_read)
 * opted in.
 *
 * Unlike sk_busy_loop() / napi_busy_loop(), this spins on the in-kernel
 * ring directly rather than polling a NAPI instance, so it is effective on
 * loopback - which delivers via the per-CPU backlog and exposes no
 * pollable napi_id. Keeping the receiver hot lets a synchronous sender's
 * small writes accumulate in the ring without a wakeup per message.
 */
static void splice_busy_loop(struct sock *sk, struct sk_psock_splice *s)
{
	unsigned long start;

	if (!sk_can_busy_loop(sk))
		return;

	start = busy_loop_current_time();
	do {
		cpu_relax();
		if (splice_recv_ready(sk, s) || signal_pending(current))
			return;
	} while (!sk_busy_loop_timeout(sk, start));
}

/* prot->sock_is_readable for paired-splice sockets. tcp_stream_is_readable()
 * (via tcp_poll() / select() / epoll) consults this to mark POLLIN when
 * sk_receive_queue is empty - we must also report data sitting in the
 * splice ring, otherwise poll-driven readers wait forever despite the
 * sender having produced bytes.
 */
static bool tcp_bpf_is_readable(struct sock *sk)
{
	struct sk_psock_splice *s;
	struct sk_psock *psock;
	bool readable = false;

	rcu_read_lock();
	psock = sk_psock(sk);
	if (psock) {
		s = rcu_dereference(psock->splice);
		if (s && splice_ring_has_data(s))
			readable = true;
		else
			readable = !list_empty(&psock->ingress_msg);
	}
	rcu_read_unlock();
	return readable;
}

/*
 * Drain the ring or sleep until the sender publishes more data.
 * A spurious wake loops back and re-waits rather than returning 0,
 * because the dispatcher's TCP/sk_msg fallback is keyed on
 * sk_receive_queue / psock->ingress_msg - neither observes the ring,
 * so returning 0 with no error would deadlock the caller in
 * tcp_msg_wait_data() that the sender's next splice_wake_sync()
 * cannot satisfy.
 *
 * Returning 0 is reserved for: EOF (peer shutdown), pair gone, or
 * sk_receive_queue gained bytes (sender dropped back to tcp_sendmsg,
 * defer to the TCP path). Errors are reported via *err.
 *
 * Caller must NOT hold sk's socket lock - this function may sleep.
 */
static int tcp_bpf_splice_recvmsg(struct sock *sk,
				  struct sk_psock *psock,
				  struct msghdr *msg, size_t len,
				  int flags, int *err)
{
	struct sk_psock_splice *s;
	size_t copied;
	long timeo;

	*err = 0;
	/* PEEK is not implemented against the ring (no peek-without-advance
	 * helper). Return 0 with no error so the dispatcher defers to the
	 * TCP path; ring contents are invisible to PEEK but the socket
	 * continues to work for normal apps.
	 */
	if (flags & MSG_PEEK)
		return 0;

	s = rcu_dereference_protected(psock->splice, 1);
	if (!s)
		return 0;

	timeo = sock_rcvtimeo(sk, flags & MSG_DONTWAIT);

	for (;;) {
		copied = splice_ring_read(s, &msg->msg_iter, len);
		if (copied)
			return copied;

		/* Stream-ordering: if the sender ever dropped back to
		 * tcp_sendmsg, those bytes are now in sk_receive_queue
		 * and predate any future ring writes (sender only writes
		 * to the ring when peer rcv_queue is empty).
		 */
		if (!skb_queue_empty(&sk->sk_receive_queue))
			return 0;

		if (sk->sk_err) {
			*err = -sk->sk_err;
			return 0;
		}
		if (sk->sk_shutdown & RCV_SHUTDOWN)
			return 0; /* EOF */
		if (!rcu_access_pointer(s->peer))
			return 0; /* Pair gone */
		if (signal_pending(current)) {
			*err = sock_intr_errno(timeo);
			return 0;
		}
		if (!timeo) {
			*err = -EAGAIN;
			return 0;
		}

		/* Spin on the ring for the SO_BUSY_POLL budget before
		 * sleeping. If the spin observes data, re-read from the
		 * loop head; otherwise (budget expired or a terminal
		 * condition) proceed to park - splice_recv_wait() returns
		 * immediately for terminal conditions.
		 */
		splice_busy_loop(sk, s);
		if (splice_ring_has_data(s))
			continue;

		timeo = splice_recv_wait(sk, s, timeo);
	}
}

static int splice_send_ring(struct sock *sk, struct sk_psock *psock,
			    struct msghdr *msg, size_t size, int flags)
{
	struct sk_psock_splice *self_s, *peer_s;
	struct sk_psock *peer;
	int total = 0;

	if (msg->msg_flags & MSG_OOB)
		return 0;

	self_s = rcu_dereference_protected(psock->splice, 1);
	if (!self_s)
		return 0;

	while (size > 0) {
		size_t done, space = 0;

		/* All peer / peer->sk accesses happen under RCU. If the ring
		 * has space, grab the peer's ring_ref before dropping RCU: that
		 * pins peer_s (and its ring) so the copy below can run outside
		 * RCU and fault/sleep normally. peer_sk is *not* pinned by the
		 * ref, so it must not be touched after rcu_read_unlock().
		 */
		peer_s = NULL;
		rcu_read_lock();
		peer = rcu_dereference(self_s->peer);
		if (peer) {
			struct sock *peer_sk = peer->sk;
			struct sk_psock_splice *ps = rcu_dereference(peer->splice);

			if (ps && READ_ONCE(ps->ring_buf) &&
			    !sk->sk_err && !(sk->sk_shutdown & SEND_SHUTDOWN) &&
			    skb_queue_empty(&peer_sk->sk_receive_queue)) {
				space = splice_ring_space(ps);
				if (space && percpu_ref_tryget_live(&ps->ring_ref))
					peer_s = ps;
			}
		}
		rcu_read_unlock();
		if (!peer_s)
			break;

		/* Holding peer_s->ring_ref: peer_s and its ring stay alive.
		 * The copy touches only the ring, never peer_sk, so a normal
		 * faulting copy is safe here.
		 */
		done = splice_ring_write(peer_s, &msg->msg_iter,
					 min(size, space));
		percpu_ref_put(&peer_s->ring_ref);

		if (!done)
			break;
		total += done;
		size  -= done;
	}

	/* Wake exactly once, after the loop, re-deref'ing peer under RCU.
	 * Doing this inside the loop would carry the _sync hint repeatedly
	 * and cost a redundant wake per wraparound iteration.
	 */
	if (total) {
		rcu_read_lock();
		peer = rcu_dereference(self_s->peer);
		if (peer)
			splice_wake_sync(peer->sk);
		rcu_read_unlock();
	}
	return total;
}

__bpf_kfunc_start_defs();

/**
 * bpf_sock_splice_pair - pair two stream sockets for opportunistic
 *			  loopback splice.
 * @peer:  the other socket, retrieved via sockhash lookup. This kfunc is
 *	   KF_RELEASE: it consumes the reference the sockhash
 *	   bpf_map_lookup_elem acquired on @peer (a sockmap/sockhash lookup
 *	   is an acquire - see is_acquire_function() in the verifier).
 *	   Consuming it here is required, not merely convenient: a sock_ops
 *	   program cannot call bpf_sk_release (the helper is not available
 *	   to that program type), so a release kfunc is the only way the
 *	   program can avoid leaking the acquired reference.
 * @skops: sock_ops context; ctx->sk is one side of the pair.
 *
 * Atomically installs the splice peering on both sides. Both sockets
 * must be SOCK_STREAM, of the same address family, with psocks attached
 * (typically via prior bpf_sock_hash_update), and neither already
 * paired. Currently only TCP_ESTABLISHED is accepted; AF_UNIX
 * SOCK_STREAM support is planned (the generic name reflects that
 * extension path).
 *
 * After this call, sendmsg attempts a direct iov-to-iov copy into the
 * peer's currently published recv iov; any bytes the splice path did
 * not consume (because the peer is not in recvmsg) fall back to the
 * normal TCP send path so the sender never blocks. Recvmsg first drains
 * the socket's TCP rcv_queue (preserving stream ordering) and otherwise
 * publishes the user iov for a sender to copy into. No skb, no sk_msg,
 * and no verdict-program involvement on the splice fast path.
 *
 * Pairing is torn down automatically on close, disconnect, shutdown, or
 * RST.
 *
 * Return: 0 on success; -EEXIST if either side is already paired (race
 * loser); -EINVAL on state validation failure; -ENOENT if no psock
 * exists on either side; -ENOMEM on splice-state allocation failure.
 */
__bpf_kfunc int bpf_sock_splice_pair(struct sock *peer,
				     struct bpf_sock_ops_kern *skops)
{
	struct sk_psock_splice *self_s, *peer_s;
	struct sk_psock *p_self, *p_peer;
	struct sock *sk;
	int ret;

	if (!skops || !peer) {
		ret = -EINVAL;
		goto out_release;
	}
	sk = skops->sk;
	if (!sk || sk == peer) {
		ret = -EINVAL;
		goto out_release;
	}

	ret = splice_validate(sk, peer);
	if (ret)
		goto out_release;

	p_self = sk_psock_get(sk);
	if (!p_self) {
		ret = -ENOENT;
		goto out_release;
	}
	p_peer = sk_psock_get(peer);
	if (!p_peer) {
		sk_psock_put(sk, p_self);
		ret = -ENOENT;
		goto out_release;
	}

	self_s = splice_get_or_alloc(p_self);
	peer_s = self_s ? splice_get_or_alloc(p_peer) : NULL;
	if (!self_s || !peer_s) {
		/* If self_s succeeded but peer_s failed, self_s stays
		 * attached to p_self; it isn't leaked (freed at psock
		 * destroy) and is reusable for a future pair attempt.
		 */
		ret = -ENOMEM;
		goto out_put;
	}

	if (splice_ring_alloc(self_s) || splice_ring_alloc(peer_s)) {
		ret = -ENOMEM;
		goto out_put;
	}

	splice_lock_pair(self_s, peer_s);
	if (self_s->peer || peer_s->peer) {
		ret = -EEXIST;
		goto out_unlock;
	}

	/* Each side keeps a psock ref on the other for the duration. */
	if (!sk_psock_get(sk)) {
		ret = -ENOENT;
		goto out_unlock;
	}
	if (!sk_psock_get(peer)) {
		sk_psock_put(sk, p_self);
		ret = -ENOENT;
		goto out_unlock;
	}
	rcu_assign_pointer(self_s->peer, p_peer);
	rcu_assign_pointer(peer_s->peer, p_self);
	ret = 0;

out_unlock:
	splice_unlock_pair(self_s, peer_s);
out_put:
	sk_psock_put(peer, p_peer);
	sk_psock_put(sk, p_self);
out_release:
	/* KF_RELEASE: consume the caller's refcount on @peer (taken by
	 * bpf_map_lookup_elem on the sockhash). All exit paths come
	 * through here.
	 */
	if (peer && sk_is_refcounted(peer))
		sock_gen_put(peer);
	return ret;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_tcp_splice_kfunc_set)
BTF_ID_FLAGS(func, bpf_sock_splice_pair, KF_RELEASE)
BTF_KFUNCS_END(bpf_tcp_splice_kfunc_set)

static const struct btf_kfunc_id_set bpf_tcp_splice_kfunc_id_set = {
	.owner = THIS_MODULE,
	.set   = &bpf_tcp_splice_kfunc_set,
};

static int __init bpf_tcp_splice_init(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_SOCK_OPS,
					 &bpf_tcp_splice_kfunc_id_set);
}
late_initcall(bpf_tcp_splice_init);

#endif /* CONFIG_BPF_SYSCALL */
