// SPDX-License-Identifier: GPL-2.0
/*
 * Author:
 *	Juntong Deng <juntong.deng@outlook.com>
 */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "test_dump_all_socket.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 100000);
} rb SEC(".maps");

extern struct task_struct *bpf_task_from_vpid(pid_t vpid) __ksym;
extern void bpf_task_release(struct task_struct *p) __ksym;

extern struct sock *bpf_sock_from_task_fd(struct task_struct *task, int fd) __ksym;
extern struct sock *bpf_sock_from_socket(struct socket *sock) __ksym;
extern void bpf_sock_release(struct sock *sk) __ksym;

extern struct socket *bpf_socket_from_file(struct file *file) __ksym;
extern struct sock_common *bpf_sock_common_from_sock(struct sock *sk) __ksym;
extern struct tcp_sock *bpf_tcp_sock_from_sock(struct sock *sk) __ksym;
extern struct udp_sock *bpf_udp_sock_from_sock(struct sock *sk) __ksym;

extern int bpf_inet_src_addr_from_socket(struct socket *sock, struct sockaddr_in *addr) __ksym;
extern int bpf_inet_dst_addr_from_socket(struct socket *sock, struct sockaddr_in *addr) __ksym;
extern int bpf_inet6_src_addr_from_socket(struct socket *sock, struct sockaddr_in6 *addr) __ksym;
extern int bpf_inet6_dst_addr_from_socket(struct socket *sock, struct sockaddr_in6 *addr) __ksym;

extern int bpf_iter_task_file_new(struct bpf_iter_task_file *it, struct task_struct *task) __ksym;
extern struct file *bpf_iter_task_file_next(struct bpf_iter_task_file *it) __ksym;
extern int bpf_iter_task_file_get_fd(struct bpf_iter_task_file *it) __ksym;
extern void bpf_iter_task_file_destroy(struct bpf_iter_task_file *it) __ksym;

SEC("crib")
int dump_udp_socket(struct prog_args *arg)
{
	int err = 0;

	struct task_struct *task = bpf_task_from_vpid(arg->pid);
	if (!task) {
		err = -1;
		goto error;
	}

	struct sock *sk = bpf_sock_from_task_fd(task, arg->sockfd);
	if (!sk) {
		err = -1;
		goto error_sock;
	}

	struct event_udp *e_udp = bpf_ringbuf_reserve(&rb, sizeof(struct event_udp), 0);
	if (!e_udp) {
		err = -2;
		goto error_buf;
	}

	struct udp_sock *up = bpf_udp_sock_from_sock(sk);

	e_udp->hdr.type = EVENT_TYPE_UDP;
	e_udp->hdr.sockfd = arg->sockfd;
	e_udp->udp_flags = BPF_CORE_READ(up, udp_flags);
	e_udp->len = BPF_CORE_READ(up, len);
	e_udp->pending = BPF_CORE_READ(up, pending);

	bpf_ringbuf_submit(e_udp, 0);

error_buf:
	bpf_sock_release(sk);
error_sock:
	bpf_task_release(task);
error:
	return err;
}

SEC("crib")
int dump_tcp_socket(struct prog_args *arg)
{
	int err = 0;

	struct task_struct *task = bpf_task_from_vpid(arg->pid);
	if (!task) {
		err = -1;
		goto error;
	}

	struct sock *sk = bpf_sock_from_task_fd(task, arg->sockfd);
	if (!sk) {
		err = -1;
		goto error_sock;
	}

	struct event_tcp *e_tcp = bpf_ringbuf_reserve(&rb, sizeof(struct event_tcp), 0);
	if (!e_tcp) {
		err = -2;
		goto error_buf;
	}

	struct tcp_sock *tp = bpf_tcp_sock_from_sock(sk);

	e_tcp->hdr.type = EVENT_TYPE_TCP;
	e_tcp->hdr.sockfd = arg->sockfd;
	e_tcp->snd_wl1 = BPF_CORE_READ(tp, snd_wl1);
	e_tcp->snd_wnd = BPF_CORE_READ(tp, snd_wnd);
	e_tcp->max_window = BPF_CORE_READ(tp, max_window);
	e_tcp->rcv_wnd = BPF_CORE_READ(tp, rcv_wnd);
	e_tcp->rcv_wup = BPF_CORE_READ(tp, rcv_wup);
	e_tcp->write_seq = BPF_CORE_READ(tp, write_seq);
	e_tcp->rcv_nxt = BPF_CORE_READ(tp, rcv_nxt);

	bpf_ringbuf_submit(e_tcp, 0);

error_buf:
	bpf_sock_release(sk);
error_sock:
	bpf_task_release(task);
error:
	return err;
}

static int dump_inet_addr(struct socket *sock, int sockfd)
{
	struct event_inet_addr *e_src_addr = bpf_ringbuf_reserve(&rb, sizeof(struct event_inet_addr), 0);
	if (!e_src_addr) {
		return -2;
	}

	struct event_inet_addr *e_dst_addr = bpf_ringbuf_reserve(&rb, sizeof(struct event_inet_addr), 0);
	if (!e_dst_addr) {
		bpf_ringbuf_discard(e_src_addr, 0);
		return -2;
	}

	e_src_addr->hdr.type = EVENT_TYPE_INET_ADDR;
	e_src_addr->hdr.subtype = EVENT_SUBTYPE_ADDR_SRC;
	e_src_addr->hdr.sockfd = sockfd;

	e_dst_addr->hdr.type = EVENT_TYPE_INET_ADDR;
	e_dst_addr->hdr.subtype = EVENT_SUBTYPE_ADDR_DST;
	e_dst_addr->hdr.sockfd = sockfd;

	bpf_inet_src_addr_from_socket(sock, &e_src_addr->addr);
	bpf_inet_dst_addr_from_socket(sock, &e_dst_addr->addr);

	bpf_ringbuf_submit(e_src_addr, 0);
	bpf_ringbuf_submit(e_dst_addr, 0);

	return 0;
}

static int dump_inet6_addr(struct socket *sock, int sockfd)
{
	struct event_inet6_addr *e_src_addr = bpf_ringbuf_reserve(&rb, sizeof(struct event_inet6_addr), 0);
	if (!e_src_addr) {
		return -2;
	}

	struct event_inet6_addr *e_dst_addr = bpf_ringbuf_reserve(&rb, sizeof(struct event_inet6_addr), 0);
	if (!e_dst_addr) {
		bpf_ringbuf_discard(e_src_addr, 0);
		return -2;
	}

	e_src_addr->hdr.type = EVENT_TYPE_INET6_ADDR;
	e_src_addr->hdr.subtype = EVENT_SUBTYPE_ADDR_SRC;
	e_src_addr->hdr.sockfd = sockfd;

	e_dst_addr->hdr.type = EVENT_TYPE_INET6_ADDR;
	e_dst_addr->hdr.subtype = EVENT_SUBTYPE_ADDR_DST;
	e_dst_addr->hdr.sockfd = sockfd;

	bpf_inet6_src_addr_from_socket(sock, &e_src_addr->addr);
	bpf_inet6_dst_addr_from_socket(sock, &e_dst_addr->addr);

	bpf_ringbuf_submit(e_src_addr, 0);
	bpf_ringbuf_submit(e_dst_addr, 0);

	return 0;
}

SEC("crib")
int dump_all_socket(struct prog_args *arg)
{
	int err = 0;

	struct task_struct *task = bpf_task_from_vpid(arg->pid);
	if (!task) {
		err = -1;
		goto error;
	}

	struct bpf_iter_task_file file_it;
	struct file *cur_file;

	bpf_iter_task_file_new(&file_it, task);
	while ((cur_file = bpf_iter_task_file_next(&file_it))) {
		struct socket *sock = bpf_socket_from_file(cur_file);
		if (!sock) {
			continue;
		}

		struct event_socket *e_socket = bpf_ringbuf_reserve(&rb, sizeof(struct event_socket), 0);
		if (!e_socket) {
			err = -2;
			goto error_buf;
		}

		struct sock *sk = bpf_sock_from_socket(sock);
		struct sock_common *sk_cm = bpf_sock_common_from_sock(sk);

		int sock_family = BPF_CORE_READ(sk_cm, skc_family);
		int sock_state = BPF_CORE_READ(sk_cm, skc_state);
		int sock_type = BPF_CORE_READ(sk, sk_type);
		int sock_protocol = BPF_CORE_READ(sk, sk_protocol);
		int fd = bpf_iter_task_file_get_fd(&file_it);

		bpf_sock_release(sk);

		e_socket->hdr.type = EVENT_TYPE_SOCKET;
		e_socket->hdr.sockfd = fd;
		e_socket->family = sock_family;
		e_socket->state = sock_state;
		e_socket->type = sock_type;
		e_socket->protocol = sock_protocol;

		bpf_ringbuf_submit(e_socket, 0);

		if (sock_family == PF_INET)
			err = dump_inet_addr(sock, fd);
		else if (sock_family == PF_INET6)
			err = dump_inet6_addr(sock, fd);

		if (err) {
			goto error_buf;
		}
	}

error_buf:
	bpf_iter_task_file_destroy(&file_it);
	bpf_task_release(task);
error:
	return err;
}
