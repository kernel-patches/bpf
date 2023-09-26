/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 Isovalent */
#ifndef __NET_META_H
#define __NET_META_H

#include <linux/bpf.h>

#ifdef CONFIG_META
int meta_prog_attach(const union bpf_attr *attr, struct bpf_prog *prog);
int meta_link_attach(const union bpf_attr *attr, struct bpf_prog *prog);
int meta_prog_detach(const union bpf_attr *attr, struct bpf_prog *prog);
int meta_prog_query(const union bpf_attr *attr, union bpf_attr __user *uattr);
#else
static inline int meta_prog_attach(const union bpf_attr *attr,
				   struct bpf_prog *prog)
{
	return -EINVAL;
}

static inline int meta_link_attach(const union bpf_attr *attr,
				   struct bpf_prog *prog)
{
	return -EINVAL;
}

static inline int meta_prog_detach(const union bpf_attr *attr,
				   struct bpf_prog *prog)
{
	return -EINVAL;
}

static inline int meta_prog_query(const union bpf_attr *attr,
				  union bpf_attr __user *uattr)
{
	return -EINVAL;
}
#endif /* CONFIG_META */
#endif /* __NET_META_H */
