// SPDX-License-Identifier: GPL-2.0
/* Copyright 2025 Google LLC */

#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "bpf_misc.h"

#define EPERM 1

#define FMODE_PATH	(1 << 14)
#define S_IFMT		00170000
#define S_IFSOCK	0140000
#define S_ISSOCK(mode)	(((mode) & S_IFMT) == S_IFSOCK)

#define AF_UNIX		1

static struct inode *file_inode(struct file *filp)
{
	return bpf_core_cast(filp->f_inode, struct inode);
}

static struct socket *SOCKET_I(struct inode *inode)
{
	return bpf_core_cast(&container_of(inode, struct socket_alloc, vfs_inode)->socket,
			     struct socket);
}

/* mostly same with unix_get_socket() in net/unix/garbage.c */
static struct sock *unix_get_socket(struct file *filp)
{
	struct socket *sock;
	struct inode *inode;

	if (filp->f_mode & FMODE_PATH)
		return NULL;

	inode = file_inode(filp);
	if (!inode)
		return NULL;

	if (!S_ISSOCK(inode->i_mode))
		return NULL;

	sock = SOCKET_I(inode);
	if (!sock || !sock->ops || sock->ops->family != AF_UNIX)
		return NULL;

	return sock->sk;
}

SEC("lsm/unix_may_send")
int BPF_PROG(unix_may_send_filter,
	     struct sock *sk, struct sock *other, struct sk_buff *skb)
{
	struct unix_skb_parms *cb;
	struct scm_fp_list *fpl;
	int i;

	if (!skb)
		return 0;

	cb = bpf_core_cast(skb->cb, struct unix_skb_parms);
	if (!cb->fp)
		return 0;

	fpl = bpf_core_cast(cb->fp, struct scm_fp_list);

	for (i = 0; i < fpl->count && i < ARRAY_SIZE(fpl->fp); i++) {
		struct file *filp;

		filp = bpf_core_cast(fpl->fp[i], struct file);

		/* self-reference is the simplest case that requires GC */
		if (unix_get_socket(filp) == other)
			return -EPERM;
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
