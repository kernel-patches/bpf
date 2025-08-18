/* SPDX-License-Identifier: GPL-2.0+ */

#ifndef __BPF_OOM_H
#define __BPF_OOM_H

struct bpf_oom;
struct oom_control;

#define BPF_OOM_NAME_MAX_LEN 64

struct bpf_oom_ops {
	/**
	 * @handle_out_of_memory: Out of memory bpf handler, called before
	 * the in-kernel OOM killer.
	 * @oc: OOM control structure
	 *
	 * Should return 1 if some memory was freed up, otherwise
	 * the in-kernel OOM killer is invoked.
	 */
	int (*handle_out_of_memory)(struct oom_control *oc);

	/**
	 * @name: BPF OOM policy name
	 */
	char name[BPF_OOM_NAME_MAX_LEN];

	/* Private */
	struct bpf_oom *bpf_oom;
};

#ifdef CONFIG_BPF_SYSCALL
/**
 * @bpf_handle_oom: handle out of memory using bpf programs
 * @oc: OOM control structure
 *
 * Returns true if a bpf oom program was executed, returned 1
 * and some memory was actually freed.
 */
bool bpf_handle_oom(struct oom_control *oc);

#else /* CONFIG_BPF_SYSCALL */
static inline bool bpf_handle_oom(struct oom_control *oc)
{
	return false;
}

#endif /* CONFIG_BPF_SYSCALL */

#endif /* __BPF_OOM_H */
