/* SPDX-License-Identifier: GPL-2.0 */
/*
 * BPF policy hooks for the memory controller.
 *
 * A bpf_memcg_ops is attached to a cgroup.  A charge runs the policies of
 * that cgroup and of every ancestor, and the kernel combines what they
 * return.  BPF only picks between things the kernel already does.
 *
 * The type has no members yet; they come with the policies that use them.
 */
#ifndef _LINUX_BPF_MEMCONTROL_H
#define _LINUX_BPF_MEMCONTROL_H

struct bpf_memcg_ops {
};

#endif /* _LINUX_BPF_MEMCONTROL_H */
