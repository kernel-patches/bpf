/* SPDX-License-Identifier: GPL-2.0+ */

#ifndef __BPF_OOM_H
#define __BPF_OOM_H

struct oom_control;

#define BPF_OOM_NAME_MAX_LEN 64

struct bpf_oom_ctx {
	/*
	 * If bpf_oom_ops is attached to a cgroup, id of this cgroup.
	 * 0 otherwise.
	 */
	u64 cgroup_id;
};

struct bpf_oom_ops {
	/**
	 * @handle_out_of_memory: Out of memory bpf handler, called before
	 * the in-kernel OOM killer.
	 * @oc: OOM control structure
	 * @ctx: Execution context
	 *
	 * Should return 1 if some memory was freed up, otherwise
	 * the in-kernel OOM killer is invoked.
	 */
	int (*handle_out_of_memory)(struct oom_control *oc, struct bpf_oom_ctx *ctx);

	/**
	 * @handle_cgroup_offline: Cgroup offline callback
	 * @cgroup_id: Id of deleted cgroup
	 *
	 * Called if the cgroup with the attached bpf_oom_ops is deleted.
	 */
	void (*handle_cgroup_offline)(u64 cgroup_id, struct bpf_oom_ctx *ctx);

	/**
	 * @name: BPF OOM policy name
	 */
	char name[BPF_OOM_NAME_MAX_LEN];
};

#ifdef CONFIG_BPF_SYSCALL
/**
 * @bpf_handle_oom: handle out of memory condition using bpf
 * @oc: OOM control structure
 *
 * Returns true if some memory was freed.
 */
bool bpf_handle_oom(struct oom_control *oc);


/**
 * @bpf_oom_memcg_offline: handle memcg offlining
 * @memcg: Memory cgroup is offlined
 *
 * When a memory cgroup is about to be deleted and there is an
 * attached BPF OOM structure, it has to be detached.
 */
void bpf_oom_memcg_offline(struct mem_cgroup *memcg);

#else /* CONFIG_BPF_SYSCALL */
static inline bool bpf_handle_oom(struct oom_control *oc)
{
	return false;
}

static inline void bpf_oom_memcg_offline(struct mem_cgroup *memcg) {}

#endif /* CONFIG_BPF_SYSCALL */

#endif /* __BPF_OOM_H */
