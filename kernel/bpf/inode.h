/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright (c) 2022 Google
 */
#ifndef __BPF_INODE_H_
#define __BPF_INODE_H_

enum bpf_type {
	BPF_TYPE_UNSPEC = 0,
	BPF_TYPE_PROG,
	BPF_TYPE_MAP,
	BPF_TYPE_LINK,
};

struct notify_ops {
	void (*free_inode)(void *object, enum bpf_type type, void *priv);
};

#ifdef CONFIG_FSNOTIFY
/* Watch the destruction of an inode and calls the callbacks in the given
 * notify_ops.
 */
int bpf_watch_inode(struct inode *inode, const struct notify_ops *ops,
		    void *priv);
#else
static inline
int bpf_watch_inode(struct inode *inode, const struct notify_ops *ops,
		    void *priv)
{
	return -EPERM;
}
#endif  // CONFIG_FSNOTIFY

#endif  // __BPF_INODE_H_
