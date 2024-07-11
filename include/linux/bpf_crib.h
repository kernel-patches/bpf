/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Checkpoint/Restore In eBPF (CRIB)
 *
 * Author:
 *	Juntong Deng <juntong.deng@outlook.com>
 */
#ifndef _BPF_CRIB_H
#define _BPF_CRIB_H

#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>

struct bpf_iter_task_file {
	__u64 __opaque[3];
} __aligned(8);

struct bpf_iter_task_file_kern {
	struct task_struct *task;
	struct file *file;
	int fd;
} __aligned(8);

struct bpf_iter_skb {
	__u64 __opaque[2];
} __aligned(8);

struct bpf_iter_skb_kern {
	struct sk_buff_head *head;
	struct sk_buff *skb;
} __aligned(8);

struct bpf_iter_skb_data {
	__u64 __opaque[5];
} __aligned(8);

struct bpf_iter_skb_data_kern {
	struct sk_buff *skb;
	char *buf;
	unsigned int buflen;
	int offset;
	unsigned int headerlen;
	unsigned int size;
	unsigned int chunklen;
} __aligned(8);

#endif /* _BPF_CRIB_H */
