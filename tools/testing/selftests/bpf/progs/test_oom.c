// SPDX-License-Identifier: GPL-2.0-only
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

#define OOM_SCORE_ADJ_MIN	(-1000)

void bpf_rcu_read_lock(void) __ksym;
void bpf_rcu_read_unlock(void) __ksym;
struct task_struct *bpf_task_acquire(struct task_struct *p) __ksym;
void bpf_task_release(struct task_struct *p) __ksym;
struct mem_cgroup *bpf_get_root_mem_cgroup(void) __ksym;
struct mem_cgroup *bpf_get_mem_cgroup(struct cgroup_subsys_state *css) __ksym;
void bpf_put_mem_cgroup(struct mem_cgroup *memcg) __ksym;
int bpf_oom_kill_process(struct oom_control *oc, struct task_struct *task,
			 const char *message__str) __ksym;

static bool mem_cgroup_killable(struct mem_cgroup *memcg)
{
	struct task_struct *task;
	bool ret = true;

	bpf_for_each(css_task, task, &memcg->css, CSS_TASK_ITER_PROCS)
		if (task->signal->oom_score_adj == OOM_SCORE_ADJ_MIN)
			return false;

	return ret;
}

/*
 * Find the largest leaf cgroup (ignoring page cache) without unkillable tasks
 * and kill all belonging tasks.
 */
SEC("struct_ops.s/handle_out_of_memory")
int BPF_PROG(test_out_of_memory, struct oom_control *oc)
{
	struct task_struct *task;
	struct mem_cgroup *root_memcg = oc->memcg;
	struct mem_cgroup *memcg, *victim = NULL;
	struct cgroup_subsys_state *css_pos;
	unsigned long usage, max_usage = 0;
	unsigned long pagecache = 0;
	int ret = 0;

	if (root_memcg)
		root_memcg = bpf_get_mem_cgroup(&root_memcg->css);
	else
		root_memcg = bpf_get_root_mem_cgroup();

	if (!root_memcg)
		return 0;

	bpf_rcu_read_lock();
	bpf_for_each(css, css_pos, &root_memcg->css, BPF_CGROUP_ITER_DESCENDANTS_POST) {
		if (css_pos->cgroup->nr_descendants + css_pos->cgroup->nr_dying_descendants)
			continue;

		memcg = bpf_get_mem_cgroup(css_pos);
		if (!memcg)
			continue;

		usage = bpf_mem_cgroup_usage(memcg);
		pagecache = bpf_mem_cgroup_page_state(memcg, NR_FILE_PAGES);

		if (usage > pagecache)
			usage -= pagecache;
		else
			usage = 0;

		if ((usage > max_usage) && mem_cgroup_killable(memcg)) {
			max_usage = usage;
			if (victim)
				bpf_put_mem_cgroup(victim);
			victim = bpf_get_mem_cgroup(&memcg->css);
		}

		bpf_put_mem_cgroup(memcg);
	}
	bpf_rcu_read_unlock();

	if (!victim)
		goto exit;

	bpf_for_each(css_task, task, &victim->css, CSS_TASK_ITER_PROCS) {
		struct task_struct *t = bpf_task_acquire(task);

		if (t) {
			if (!bpf_task_is_oom_victim(task))
				bpf_oom_kill_process(oc, task, "bpf oom test");
			bpf_task_release(t);
			ret = 1;
		}
	}

	bpf_put_mem_cgroup(victim);
exit:
	bpf_put_mem_cgroup(root_memcg);

	return ret;
}

SEC(".struct_ops.link")
struct bpf_oom_ops test_bpf_oom = {
	.name = "bpf_test_policy",
	.handle_out_of_memory = (void *)test_out_of_memory,
};
