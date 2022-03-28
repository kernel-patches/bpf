/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BPF_PRELOAD_H
#define _BPF_PRELOAD_H

enum bpf_type {
	BPF_TYPE_UNSPEC	= 0,
	BPF_TYPE_PROG,
	BPF_TYPE_MAP,
	BPF_TYPE_LINK,
};

struct bpf_preload_ops {
	int (*preload)(struct dentry *parent);
	struct module *owner;
};

#ifdef CONFIG_BPF_SYSCALL
extern struct bpf_preload_ops *bpf_preload_ops;

int bpf_obj_do_pin_kernel(struct dentry *parent, const char *name, void *raw,
			  enum bpf_type type);
#else
static inline int bpf_obj_do_pin_kernel(struct dentry *parent, const char *name,
					void *raw, enum bpf_type type)
{
	return -EOPNOTSUPP;
}
#endif /*CONFIG_BPF_SYSCALL*/

#endif
