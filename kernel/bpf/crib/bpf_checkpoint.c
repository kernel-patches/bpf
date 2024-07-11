// SPDX-License-Identifier: GPL-2.0
/*
 * Checkpoint/Restore In eBPF (CRIB): Checkpoint
 *
 * Author:
 *	Juntong Deng <juntong.deng@outlook.com>
 */

#include <linux/bpf_crib.h>
#include <linux/fdtable.h>
#include <net/inet_common.h>
#include <net/ipv6.h>
#include <linux/skbuff.h>

extern void bpf_file_release(struct file *file);

extern struct sk_buff *bpf_skb_acquire(struct sk_buff *skb);

extern void bpf_skb_release(struct sk_buff *skb);

__bpf_kfunc_start_defs();

/**
 * bpf_iter_task_file_new() - Initialize a new task file iterator for a task,
 * used to iterate over all files opened by a specified task
 *
 * @it: The new bpf_iter_task_file to be created
 * @task: A pointer pointing to a task to be iterated over
 */
__bpf_kfunc int bpf_iter_task_file_new(struct bpf_iter_task_file *it,
		struct task_struct *task)
{
	struct bpf_iter_task_file_kern *kit = (void *)it;

	BUILD_BUG_ON(sizeof(struct bpf_iter_task_file_kern) > sizeof(struct bpf_iter_task_file));
	BUILD_BUG_ON(__alignof__(struct bpf_iter_task_file_kern) !=
		     __alignof__(struct bpf_iter_task_file));

	kit->task = task;
	kit->fd = -1;
	kit->file = NULL;

	return 0;
}

/**
 * bpf_iter_task_file_next() - Get the next file in bpf_iter_task_file
 *
 * bpf_iter_task_file_next() acquires a reference to the returned struct file.
 *
 * The reference to struct file acquired by the previous
 * bpf_iter_task_file_next() is released in the next bpf_iter_task_file_next(),
 * and the last reference is released in the last bpf_iter_task_file_next()
 * that returns NULL.
 *
 * @it: The bpf_iter_task_file to be checked
 *
 * @returns a pointer to the struct file of the next file if further files
 * are available, otherwise returns NULL.
 */
__bpf_kfunc struct file *bpf_iter_task_file_next(struct bpf_iter_task_file *it)
{
	struct bpf_iter_task_file_kern *kit = (void *)it;

	if (kit->file)
		bpf_file_release(kit->file);

	kit->fd++;

	rcu_read_lock();
	kit->file = task_lookup_next_fdget_rcu(kit->task, &kit->fd);
	rcu_read_unlock();

	return kit->file;
}

/**
 * bpf_iter_task_file_get_fd() - Get the file descriptor
 * corresponding to the file in the current iteration
 *
 * @it: The bpf_iter_task_file to be checked
 *
 * @returns the file descriptor
 */
__bpf_kfunc int bpf_iter_task_file_get_fd(struct bpf_iter_task_file *it)
{
	struct bpf_iter_task_file_kern *kit = (void *)it;

	return kit->fd;
}

/**
 * bpf_iter_task_file_destroy() - Destroy a bpf_iter_task_file
 *
 * If the iterator does not iterate to the end, then the last
 * struct file reference is released at this time.
 *
 * @it: The bpf_iter_task_file to be destroyed
 */
__bpf_kfunc void bpf_iter_task_file_destroy(struct bpf_iter_task_file *it)
{
	struct bpf_iter_task_file_kern *kit = (void *)it;

	if (kit->file)
		bpf_file_release(kit->file);
}

/**
 * bpf_inet_src_addr_from_socket() - Wrap inet_getname to get the source
 * IPv4 address and source port of the specified socket
 *
 * @sock: specified socket
 * @addr: buffer
 */
__bpf_kfunc int bpf_inet_src_addr_from_socket(struct socket *sock, struct sockaddr_in *addr)
{
	return inet_getname(sock, (struct sockaddr *)addr, 0);
}

/**
 * bpf_inet_dst_addr_from_socket() - Wrap inet_getname to get the destination
 * IPv4 address and destination port of the specified socket
 *
 * @sock: specified socket
 * @addr: buffer
 */
__bpf_kfunc int bpf_inet_dst_addr_from_socket(struct socket *sock, struct sockaddr_in *addr)
{
	return inet_getname(sock, (struct sockaddr *)addr, 1);
}

/**
 * bpf_inet6_src_addr_from_socket() - Wrap inet6_getname to get the source
 * IPv6 address and source port of the specified socket
 *
 * @sock: specified socket
 * @addr: buffer
 */
__bpf_kfunc int bpf_inet6_src_addr_from_socket(struct socket *sock, struct sockaddr_in6 *addr)
{
	return inet6_getname(sock, (struct sockaddr *)addr, 0);
}

/**
 * bpf_inet6_dst_addr_from_socket() - Wrap inet6_getname to get the destination
 * IPv6 address and destination port of the specified socket
 *
 * @sock: specified socket
 * @addr: buffer
 */
__bpf_kfunc int bpf_inet6_dst_addr_from_socket(struct socket *sock, struct sockaddr_in6 *addr)
{
	return inet6_getname(sock, (struct sockaddr *)addr, 1);
}

/**
 * bpf_cal_skb_size() - Calculate the overall size of the data of specified skb
 * (starting from the head)
 *
 * @skb: specified skb
 *
 * @returns the overall size of the data
 */
__bpf_kfunc int bpf_cal_skb_size(struct sk_buff *skb)
{
	return skb_end_offset(skb) + skb->data_len;
}

/**
 * bpf_iter_skb_new() - Initialize a new skb iterator for a socket
 * queue (sk_buff_head), used to iterates over all skb in the specified
 * socket queue
 *
 * @it: The new bpf_iter_skb to be created
 * @head: A pointer pointing to a sk_buff_head to be iterated over
 */
__bpf_kfunc int bpf_iter_skb_new(struct bpf_iter_skb *it,
		struct sk_buff_head *head)
{
	struct bpf_iter_skb_kern *kit = (void *)it;

	BUILD_BUG_ON(sizeof(struct bpf_iter_skb_kern) != sizeof(struct bpf_iter_skb));
	BUILD_BUG_ON(__alignof__(struct bpf_iter_skb_kern) != __alignof__(struct bpf_iter_skb));

	kit->head = head;
	kit->skb = NULL;

	return 0;
}

/**
 * bpf_iter_skb_next() - Get the next skb in bpf_iter_skb
 *
 * bpf_iter_skb_next() acquires a reference to the returned struct sk_buff.
 *
 * The reference to struct sk_buff acquired by the previous bpf_iter_skb_next()
 * is released in the next bpf_iter_skb_next(), and the last reference is
 * released in the last bpf_iter_skb_next() that returns NULL.
 *
 * @it: bpf_iter_skb to be checked
 *
 * @returns a pointer to the struct sk_buff of the next skb if further skbs
 * are available, otherwise returns NULL.
 */
__bpf_kfunc struct sk_buff *bpf_iter_skb_next(struct bpf_iter_skb *it)
{
	struct bpf_iter_skb_kern *kit = (void *)it;
	unsigned long flags;

	if (kit->skb)
		bpf_skb_release(kit->skb);

	spin_lock_irqsave(&kit->head->lock, flags);

	if (!kit->skb)
		kit->skb = skb_peek(kit->head);
	else
		kit->skb = skb_peek_next(kit->skb, kit->head);

	spin_unlock_irqrestore(&kit->head->lock, flags);

	if (kit->skb)
		bpf_skb_acquire(kit->skb);

	return kit->skb;
}

/**
 * bpf_iter_skb_destroy() - Destroy a bpf_iter_skb
 *
 * If the iterator does not iterate to the end, then the last
 * struct sk_buff reference is released at this time.
 *
 * @it: bpf_iter_skb to be destroyed
 */
__bpf_kfunc void bpf_iter_skb_destroy(struct bpf_iter_skb *it)
{
	struct bpf_iter_skb_kern *kit = (void *)it;

	if (kit->skb)
		bpf_skb_release(kit->skb);
}

__bpf_kfunc_end_defs();
