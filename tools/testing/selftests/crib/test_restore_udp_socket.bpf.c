// SPDX-License-Identifier: GPL-2.0
/*
 * Author:
 *	Juntong Deng <juntong.deng@outlook.com>
 */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "test_restore_udp_socket.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 100000);
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_USER_RINGBUF);
	__uint(max_entries, 100000);
} urb SEC(".maps");

extern struct task_struct *bpf_task_from_vpid(pid_t vpid) __ksym;
extern void bpf_task_release(struct task_struct *p) __ksym;

extern struct sock *bpf_sock_from_task_fd(struct task_struct *task, int fd) __ksym;
extern void bpf_sock_release(struct sock *sk) __ksym;

extern struct udp_sock *bpf_udp_sock_from_sock(struct sock *sk) __ksym;
extern struct sk_buff_head *bpf_receive_queue_from_sock(struct sock *sk)  __ksym;
extern struct sk_buff_head *bpf_write_queue_from_sock(struct sock *sk) __ksym;
extern struct sk_buff_head *bpf_reader_queue_from_udp_sock(struct udp_sock *up) __ksym;

extern int bpf_iter_skb_new(struct bpf_iter_skb *it, struct sk_buff_head *head) __ksym;
extern struct sk_buff *bpf_iter_skb_next(struct bpf_iter_skb *it) __ksym;
extern void bpf_iter_skb_destroy(struct bpf_iter_skb *it) __ksym;

extern int bpf_iter_skb_data_new(struct bpf_iter_skb_data *it, struct sk_buff *skb, char *buf, int buflen) __ksym;
extern char *bpf_iter_skb_data_next(struct bpf_iter_skb_data *it) __ksym;
extern void bpf_iter_skb_data_set_buf(struct bpf_iter_skb_data *it, char *buf, int buflen) __ksym;
extern int bpf_iter_skb_data_get_chunk_len(struct bpf_iter_skb_data *it) __ksym;
extern int bpf_iter_skb_data_get_offset(struct bpf_iter_skb_data *it) __ksym;
extern void bpf_iter_skb_data_destroy(struct bpf_iter_skb_data *it) __ksym;

extern int bpf_cal_skb_size(struct sk_buff *skb) __ksym;
extern struct sk_buff *bpf_skb_peek_tail(struct sk_buff_head *head) __ksym;
extern void bpf_skb_release(struct sk_buff *skb) __ksym;

extern struct sk_buff *bpf_restore_skb_rcv_queue(struct sk_buff_head *head, struct sock *sk,
						 struct bpf_crib_skb_info *skb_info) __ksym;
extern int bpf_restore_skb_data(struct sk_buff *skb, int offset, char *data, int len) __ksym;

static int dump_skb_data(struct sk_buff *skb, int subtype, int skb_num)
{
	struct bpf_iter_skb_data skb_data_it;
	int err = 0;

	/*
	 * Since bpf_iter_skb_data_next will dump the skb data into the buffer,
	 * the buffer needs to be allocated in advance
	 */
	struct event_skb_data *e_skb_data;
	e_skb_data = bpf_ringbuf_reserve(&rb, sizeof(struct event_skb_data), 0);
	if (!e_skb_data) {
		err = -2;
		goto error_buf;
	}

	bpf_iter_skb_data_new(&skb_data_it, skb, e_skb_data->buf, sizeof(e_skb_data->buf));
	while (bpf_iter_skb_data_next(&skb_data_it)) {
		e_skb_data->hdr.type = EVENT_TYPE_SKB_DATA;
		e_skb_data->hdr.subtype = subtype;
		e_skb_data->skb_num = skb_num;
		e_skb_data->chunk_length = bpf_iter_skb_data_get_chunk_len(&skb_data_it);
		e_skb_data->offset = bpf_iter_skb_data_get_offset(&skb_data_it);
		bpf_ringbuf_submit(e_skb_data, 0);

		/*
		 * For the same reason as above, the buffer used in
		 * the next iteration needs to be allocated now
		 */
		e_skb_data = bpf_ringbuf_reserve(&rb, sizeof(struct event_skb_data), 0);
		if (!e_skb_data) {
			err = -2;
			goto error_in_buf;
		}

		bpf_iter_skb_data_set_buf(&skb_data_it, e_skb_data->buf, sizeof(e_skb_data->buf));
	}
	/* Discard the pre-allocated buffer in the last iteration (it will not be used) */
	bpf_ringbuf_discard(e_skb_data, 0);

error_in_buf:
	bpf_iter_skb_data_destroy(&skb_data_it);
error_buf:
	return err;
}

static int dump_all_queue_skb(struct sk_buff_head *head, int subtype)
{
	struct bpf_iter_skb skb_it;
	struct sk_buff *cur_skb;
	int skb_num = 0;
	int err = 0;

	bpf_iter_skb_new(&skb_it, head);
	while ((cur_skb = bpf_iter_skb_next(&skb_it))) {
		struct event_skb *e_skb = bpf_ringbuf_reserve(&rb, sizeof(struct event_skb), 0);
		if (!e_skb) {
			err = -2;
			goto error;
		}

		e_skb->hdr.type = EVENT_TYPE_SKB;
		e_skb->hdr.subtype = subtype;
		e_skb->skb_num = skb_num;
		e_skb->len = BPF_CORE_READ(cur_skb, len);
		e_skb->tstamp = BPF_CORE_READ(cur_skb, tstamp);
		e_skb->dev_scratch = BPF_CORE_READ(cur_skb, dev_scratch);
		e_skb->protocol = BPF_CORE_READ(cur_skb, protocol);
		e_skb->transport_header = BPF_CORE_READ(cur_skb, transport_header);
		e_skb->network_header = BPF_CORE_READ(cur_skb, network_header);
		e_skb->mac_header = BPF_CORE_READ(cur_skb, mac_header);
		e_skb->csum = BPF_CORE_READ(cur_skb, csum);
		e_skb->csum = BPF_CORE_READ(cur_skb, csum);
		e_skb->size = bpf_cal_skb_size(cur_skb);

		unsigned char *head = BPF_CORE_READ(cur_skb, head);
		unsigned char *data = BPF_CORE_READ(cur_skb, data);
		e_skb->headerlen = data - head; //skb_headroom

		bpf_ringbuf_submit(e_skb, 0);

		if (dump_skb_data(cur_skb, subtype, skb_num) != 0) {
			err = -1;
			goto error;
		}

		skb_num++;
	}
error:
	bpf_iter_skb_destroy(&skb_it);
	return err;
}

int dump_write_queue_skb(struct sock *sk)
{
	struct sk_buff_head *write_queue_head = bpf_write_queue_from_sock(sk);
	return dump_all_queue_skb(write_queue_head, EVENT_SUBTYPE_WRITE_QUEUE);
}

int dump_receive_queue_skb(struct sock *sk)
{
	struct sk_buff_head *receive_queue_head = bpf_receive_queue_from_sock(sk);
	return dump_all_queue_skb(receive_queue_head, EVENT_SUBTYPE_RECEIVE_QUEUE);
}

int dump_reader_queue_skb(struct sock *sk)
{
	struct udp_sock *up = bpf_udp_sock_from_sock(sk);
	struct sk_buff_head *reader_queue_head = bpf_reader_queue_from_udp_sock(up);
	return dump_all_queue_skb(reader_queue_head, EVENT_SUBTYPE_READER_QUEUE);
}

SEC("crib")
int dump_socket_queue(struct prog_args *arg)
{
	int err = 0;

	struct task_struct *task = bpf_task_from_vpid(arg->pid);
	if (!task) {
		err = -1;
		goto error;
	}

	struct sock *sk = bpf_sock_from_task_fd(task, arg->fd);
	if (!sk) {
		err = -1;
		goto error_sock;
	}

	dump_write_queue_skb(sk);
	dump_receive_queue_skb(sk);
	dump_reader_queue_skb(sk);

	struct event_hdr *e_dump_end = bpf_ringbuf_reserve(&rb, sizeof(struct event_hdr), 0);
	if (!e_dump_end) {
		err = -2;
		goto error_buf;
	}

	e_dump_end->type = EVENT_TYPE_END;
	bpf_ringbuf_submit(e_dump_end, 0);

error_buf:
	bpf_sock_release(sk);
error_sock:
	bpf_task_release(task);
error:
	return err;
}

static int handle_restore_skb_data(struct event_skb_data *e_skb_data, struct sk_buff_head *head)
{
	struct sk_buff *skb = bpf_skb_peek_tail(head);
	if (!skb)
		return -1;

	bpf_restore_skb_data(skb, e_skb_data->offset, e_skb_data->buf, e_skb_data->chunk_length);

	bpf_skb_release(skb);
	return 0;
}

static int handle_restore_skb(struct event_skb *e_skb, struct sk_buff_head *head, struct sock *sk)
{
	struct bpf_crib_skb_info skb_info;
	skb_info.headerlen = e_skb->headerlen;
	skb_info.len = e_skb->len;
	skb_info.size = e_skb->size;
	skb_info.tstamp = e_skb->tstamp;
	skb_info.dev_scratch = e_skb->dev_scratch;
	skb_info.protocol = e_skb->protocol;
	skb_info.csum = e_skb->csum;
	skb_info.transport_header = e_skb->transport_header;
	skb_info.network_header = e_skb->network_header;
	skb_info.mac_header = e_skb->mac_header;

	struct sk_buff *skb = bpf_restore_skb_rcv_queue(head, sk, &skb_info);
	if (!skb)
		return -1;

	bpf_skb_release(skb);
	return 0;
}

static long handle_restore_event(struct bpf_dynptr *dynptr, void *context)
{
	struct prog_args *arg_context = (struct prog_args *)context;
	int err = 0;

	struct task_struct *task = bpf_task_from_vpid(arg_context->pid);
	if (!task) {
		err = 1;
		goto error;
	}

	struct sock *sk = bpf_sock_from_task_fd(task, arg_context->fd);
	if (!sk) {
		err = 1;
		goto error_sock;
	}

	struct udp_sock *up = bpf_udp_sock_from_sock(sk);

	struct sk_buff_head *reader_queue = bpf_reader_queue_from_udp_sock(up);
	struct sk_buff_head *receive_queue = bpf_receive_queue_from_sock(sk);

	struct event_hdr *e_hdr = bpf_dynptr_data(dynptr, 0, sizeof(struct event_hdr));
	if (!e_hdr) {
		err = 1;
		goto error_dynptr;
	}

	if (e_hdr->type == EVENT_TYPE_SKB) {
		struct event_skb *e_skb = bpf_dynptr_data(dynptr, 0, sizeof(struct event_skb));
		if (!e_skb) {
			err = 1;
			goto error_dynptr;
		}

		if (e_hdr->subtype == EVENT_SUBTYPE_RECEIVE_QUEUE)
			handle_restore_skb(e_skb, receive_queue, sk);
		else if (e_hdr->subtype == EVENT_SUBTYPE_READER_QUEUE)
			handle_restore_skb(e_skb, reader_queue, sk);
	} else if (e_hdr->type == EVENT_TYPE_SKB_DATA) {
		struct event_skb_data *e_skb_data = bpf_dynptr_data(dynptr, 0, sizeof(struct event_skb_data));
		if (!e_skb_data) {
			err = 1;
			goto error_dynptr;
		}

		if (e_hdr->subtype == EVENT_SUBTYPE_RECEIVE_QUEUE)
			handle_restore_skb_data(e_skb_data, receive_queue);
		else if (e_hdr->subtype == EVENT_SUBTYPE_READER_QUEUE)
			handle_restore_skb_data(e_skb_data, reader_queue);
	}

error_dynptr:
	bpf_sock_release(sk);
error_sock:
	bpf_task_release(task);
error:
	return err;
}

SEC("crib")
int restore_socket_queue(struct prog_args *arg)
{
	struct prog_args arg_context = {
		.fd = arg->fd,
		.pid = arg->pid
	};

	bpf_user_ringbuf_drain(&urb, handle_restore_event, &arg_context, 0);
	return 0;
}
