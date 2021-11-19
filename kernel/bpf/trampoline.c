// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2019 Facebook */
#include <linux/hash.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/ftrace.h>
#include <linux/rbtree_latch.h>
#include <linux/perf_event.h>
#include <linux/btf.h>
#include <linux/rcupdate_trace.h>
#include <linux/rcupdate_wait.h>
#include <linux/module.h>
#include <linux/static_call.h>
#include <linux/bpf_verifier.h>

/* dummy _ops. The verifier will operate on target program's ops. */
const struct bpf_verifier_ops bpf_extension_verifier_ops = {
};
const struct bpf_prog_ops bpf_extension_prog_ops = {
};

/* btf_vmlinux has ~22k attachable functions. 1k htab is enough. */
#define TRAMPOLINE_HASH_BITS 10
#define TRAMPOLINE_TABLE_SIZE (1 << TRAMPOLINE_HASH_BITS)

static struct hlist_head trampoline_table[TRAMPOLINE_TABLE_SIZE];

/* serializes access to trampoline_table */
static DEFINE_MUTEX(trampoline_mutex);

void *bpf_jit_alloc_exec_page(void)
{
	void *image;

	image = bpf_jit_alloc_exec(PAGE_SIZE);
	if (!image)
		return NULL;

	set_vm_flush_reset_perms(image);
	/* Keep image as writeable. The alternative is to keep flipping ro/rw
	 * everytime new program is attached or detached.
	 */
	set_memory_x((long)image, 1);
	return image;
}

void bpf_image_ksym_add(void *data, struct bpf_ksym *ksym)
{
	ksym->start = (unsigned long) data;
	ksym->end = ksym->start + PAGE_SIZE;
	bpf_ksym_add(ksym);
	perf_event_ksymbol(PERF_RECORD_KSYMBOL_TYPE_BPF, ksym->start,
			   PAGE_SIZE, false, ksym->name);
}

void bpf_image_ksym_del(struct bpf_ksym *ksym)
{
	bpf_ksym_del(ksym);
	perf_event_ksymbol(PERF_RECORD_KSYMBOL_TYPE_BPF, ksym->start,
			   PAGE_SIZE, true, ksym->name);
}

static bool bpf_tramp_id_is_multi(struct bpf_tramp_id *id)
{
	return id->cnt > 1;
}

static u64 bpf_tramp_id_key(struct bpf_tramp_id *id)
{
	if (bpf_tramp_id_is_multi(id))
		return (u64) &id;
	else
		return ((u64) id->obj_id << 32) | id->id[0];
}

bool bpf_tramp_id_is_empty(struct bpf_tramp_id *id)
{
	return !id || id->cnt == 0;
}

int bpf_tramp_id_is_equal(struct bpf_tramp_id *a,
			  struct bpf_tramp_id *b)
{
	return a->obj_id == b->obj_id && a->cnt == b->cnt &&
	       !memcmp(a->id, b->id, a->cnt * sizeof(*a->id));
}

struct bpf_tramp_id *bpf_tramp_id_alloc(u32 max)
{
	struct bpf_tramp_id *id;

	id = kzalloc(sizeof(*id), GFP_KERNEL);
	if (id) {
		id->id = kzalloc(sizeof(u32) * max, GFP_KERNEL);
		id->addr = kzalloc(sizeof(*id->addr) * max, GFP_KERNEL);
		if (!id->id || !id->addr) {
			kfree(id->id);
			kfree(id->addr);
			kfree(id);
			return NULL;
		}
		id->max = max;
	}
	return id;
}

struct bpf_tramp_id *bpf_tramp_id_single(const struct bpf_prog *tgt_prog,
					 struct bpf_prog *prog, u32 btf_id,
					 struct bpf_attach_target_info *tgt_info)
{
	struct bpf_tramp_id *id;

	if (!tgt_info) {
		struct bpf_attach_target_info __tgt_info = {};
		int err;

		tgt_info = &__tgt_info;
		err = bpf_check_attach_target(NULL, prog, tgt_prog, btf_id,
					     tgt_info);
		if (err)
			return ERR_PTR(err);
	}
	id = bpf_tramp_id_alloc(1);
	if (!id)
		return ERR_PTR(-ENOMEM);
	if (tgt_prog)
		id->obj_id = tgt_prog->aux->id;
	else
		id->obj_id = btf_obj_id(prog->aux->attach_btf);
	id->id[0] = btf_id;
	id->addr[0] = (void *) tgt_info->tgt_addr;
	id->cnt = 1;
	return id;
}

void bpf_tramp_id_free(struct bpf_tramp_id *id)
{
	if (!id)
		return;
	kfree(id->addr);
	kfree(id->id);
	kfree(id);
}

static struct bpf_trampoline *bpf_trampoline_get(struct bpf_tramp_id *id)
{
	struct bpf_trampoline *tr;
	struct hlist_head *head;
	u64 key;
	int i;

	key = bpf_tramp_id_key(id);
	mutex_lock(&trampoline_mutex);
	head = &trampoline_table[hash_64(key, TRAMPOLINE_HASH_BITS)];
	hlist_for_each_entry(tr, head, hlist) {
		if (bpf_tramp_id_is_equal(tr->id, id)) {
			refcount_inc(&tr->refcnt);
			goto out;
		}
	}
	tr = kzalloc(sizeof(*tr), GFP_KERNEL);
	if (!tr)
		goto out;

	tr->id = id;
	INIT_HLIST_NODE(&tr->hlist);
	hlist_add_head(&tr->hlist, head);
	refcount_set(&tr->refcnt, 1);
	mutex_init(&tr->mutex);
	for (i = 0; i < BPF_TRAMP_MAX; i++)
		INIT_HLIST_HEAD(&tr->progs_hlist[i]);
out:
	mutex_unlock(&trampoline_mutex);
	return tr;
}

static int bpf_trampoline_module_get(struct bpf_trampoline *tr)
{
	struct module *mod;
	int err = 0;

	preempt_disable();
	mod = __module_text_address((unsigned long) tr->id->addr[0]);
	if (mod && !try_module_get(mod))
		err = -ENOENT;
	preempt_enable();
	tr->mod = mod;
	return err;
}

static void bpf_trampoline_module_put(struct bpf_trampoline *tr)
{
	module_put(tr->mod);
	tr->mod = NULL;
}

static int is_ftrace_location(void *ip)
{
	long addr;

	addr = ftrace_location((long)ip);
	if (!addr)
		return 0;
	if (WARN_ON_ONCE(addr != (long)ip))
		return -EFAULT;
	return 1;
}

static int unregister_fentry(struct bpf_trampoline *tr, void *old_addr)
{
	void *ip = tr->id->addr[0];
	int ret;

	if (tr->func.ftrace_managed)
		ret = unregister_ftrace_direct((long)ip, (long)old_addr);
	else
		ret = bpf_arch_text_poke(ip, BPF_MOD_CALL, old_addr, NULL);

	if (!ret)
		bpf_trampoline_module_put(tr);
	return ret;
}

static int modify_fentry(struct bpf_trampoline *tr, void *old_addr, void *new_addr)
{
	void *ip = tr->id->addr[0];
	int ret;

	if (tr->func.ftrace_managed)
		ret = modify_ftrace_direct((long)ip, (long)old_addr, (long)new_addr);
	else
		ret = bpf_arch_text_poke(ip, BPF_MOD_CALL, old_addr, new_addr);
	return ret;
}

/* first time registering */
static int register_fentry(struct bpf_trampoline *tr, void *new_addr)
{
	void *ip = tr->id->addr[0];
	int ret;

	ret = is_ftrace_location(ip);
	if (ret < 0)
		return ret;
	tr->func.ftrace_managed = ret;

	if (bpf_trampoline_module_get(tr))
		return -ENOENT;

	if (tr->func.ftrace_managed)
		ret = register_ftrace_direct((long)ip, (long)new_addr);
	else
		ret = bpf_arch_text_poke(ip, BPF_MOD_CALL, NULL, new_addr);

	if (ret)
		bpf_trampoline_module_put(tr);
	return ret;
}

static struct bpf_tramp_progs *
bpf_trampoline_get_progs(const struct bpf_trampoline *tr, int *total, bool *ip_arg)
{
	struct bpf_tramp_progs *tprogs;
	struct bpf_tramp_node *node;
	struct bpf_prog **progs;
	int kind;

	*total = 0;
	tprogs = kcalloc(BPF_TRAMP_MAX, sizeof(*tprogs), GFP_KERNEL);
	if (!tprogs)
		return ERR_PTR(-ENOMEM);

	for (kind = 0; kind < BPF_TRAMP_MAX; kind++) {
		tprogs[kind].nr_progs = tr->progs_cnt[kind];
		*total += tr->progs_cnt[kind];
		progs = tprogs[kind].progs;

		hlist_for_each_entry(node, &tr->progs_hlist[kind], hlist_tramp) {
			*ip_arg |= node->prog->call_get_func_ip;
			*progs++ = node->prog;
		}
	}
	return tprogs;
}

static void __bpf_tramp_image_put_deferred(struct work_struct *work)
{
	struct bpf_tramp_image *im;

	im = container_of(work, struct bpf_tramp_image, work);
	bpf_image_ksym_del(&im->ksym);
	bpf_jit_free_exec(im->image);
	bpf_jit_uncharge_modmem(1);
	percpu_ref_exit(&im->pcref);
	kfree_rcu(im, rcu);
}

/* callback, fexit step 3 or fentry step 2 */
static void __bpf_tramp_image_put_rcu(struct rcu_head *rcu)
{
	struct bpf_tramp_image *im;

	im = container_of(rcu, struct bpf_tramp_image, rcu);
	INIT_WORK(&im->work, __bpf_tramp_image_put_deferred);
	schedule_work(&im->work);
}

/* callback, fexit step 2. Called after percpu_ref_kill confirms. */
static void __bpf_tramp_image_release(struct percpu_ref *pcref)
{
	struct bpf_tramp_image *im;

	im = container_of(pcref, struct bpf_tramp_image, pcref);
	call_rcu_tasks(&im->rcu, __bpf_tramp_image_put_rcu);
}

/* callback, fexit or fentry step 1 */
static void __bpf_tramp_image_put_rcu_tasks(struct rcu_head *rcu)
{
	struct bpf_tramp_image *im;

	im = container_of(rcu, struct bpf_tramp_image, rcu);
	if (im->ip_after_call)
		/* the case of fmod_ret/fexit trampoline and CONFIG_PREEMPTION=y */
		percpu_ref_kill(&im->pcref);
	else
		/* the case of fentry trampoline */
		call_rcu_tasks(&im->rcu, __bpf_tramp_image_put_rcu);
}

static void bpf_tramp_image_put(struct bpf_tramp_image *im)
{
	/* The trampoline image that calls original function is using:
	 * rcu_read_lock_trace to protect sleepable bpf progs
	 * rcu_read_lock to protect normal bpf progs
	 * percpu_ref to protect trampoline itself
	 * rcu tasks to protect trampoline asm not covered by percpu_ref
	 * (which are few asm insns before __bpf_tramp_enter and
	 *  after __bpf_tramp_exit)
	 *
	 * The trampoline is unreachable before bpf_tramp_image_put().
	 *
	 * First, patch the trampoline to avoid calling into fexit progs.
	 * The progs will be freed even if the original function is still
	 * executing or sleeping.
	 * In case of CONFIG_PREEMPT=y use call_rcu_tasks() to wait on
	 * first few asm instructions to execute and call into
	 * __bpf_tramp_enter->percpu_ref_get.
	 * Then use percpu_ref_kill to wait for the trampoline and the original
	 * function to finish.
	 * Then use call_rcu_tasks() to make sure few asm insns in
	 * the trampoline epilogue are done as well.
	 *
	 * In !PREEMPT case the task that got interrupted in the first asm
	 * insns won't go through an RCU quiescent state which the
	 * percpu_ref_kill will be waiting for. Hence the first
	 * call_rcu_tasks() is not necessary.
	 */
	if (im->ip_after_call) {
		int err = bpf_arch_text_poke(im->ip_after_call, BPF_MOD_JUMP,
					     NULL, im->ip_epilogue);
		WARN_ON(err);
		if (IS_ENABLED(CONFIG_PREEMPTION))
			call_rcu_tasks(&im->rcu, __bpf_tramp_image_put_rcu_tasks);
		else
			percpu_ref_kill(&im->pcref);
		return;
	}

	/* The trampoline without fexit and fmod_ret progs doesn't call original
	 * function and doesn't use percpu_ref.
	 * Use call_rcu_tasks_trace() to wait for sleepable progs to finish.
	 * Then use call_rcu_tasks() to wait for the rest of trampoline asm
	 * and normal progs.
	 */
	call_rcu_tasks_trace(&im->rcu, __bpf_tramp_image_put_rcu_tasks);
}

static struct bpf_tramp_image*
bpf_tramp_image_alloc(struct bpf_tramp_id *id, u32 idx)
{
	struct bpf_tramp_image *im;
	struct bpf_ksym *ksym;
	void *image;
	int err = -ENOMEM;
	u64 key;

	im = kzalloc(sizeof(*im), GFP_KERNEL);
	if (!im)
		goto out;

	err = bpf_jit_charge_modmem(1);
	if (err)
		goto out_free_im;

	err = -ENOMEM;
	im->image = image = bpf_jit_alloc_exec_page();
	if (!image)
		goto out_uncharge;

	err = percpu_ref_init(&im->pcref, __bpf_tramp_image_release, 0, GFP_KERNEL);
	if (err)
		goto out_free_image;

	ksym = &im->ksym;
	INIT_LIST_HEAD_RCU(&ksym->lnode);
	key = bpf_tramp_id_key(id);
	snprintf(ksym->name, KSYM_NAME_LEN, "bpf_trampoline_%llu_%u%s", key, idx,
		 bpf_tramp_id_is_multi(id) ? "_multi" : "");
	bpf_image_ksym_add(image, ksym);
	return im;

out_free_image:
	bpf_jit_free_exec(im->image);
out_uncharge:
	bpf_jit_uncharge_modmem(1);
out_free_im:
	kfree(im);
out:
	return ERR_PTR(err);
}

static int bpf_trampoline_update(struct bpf_trampoline *tr)
{
	struct bpf_tramp_image *im;
	struct bpf_tramp_progs *tprogs;
	u32 flags = BPF_TRAMP_F_RESTORE_REGS;
	bool ip_arg = false;
	int err, total;

	tprogs = bpf_trampoline_get_progs(tr, &total, &ip_arg);
	if (IS_ERR(tprogs))
		return PTR_ERR(tprogs);

	if (total == 0) {
		err = unregister_fentry(tr, tr->cur_image->image);
		bpf_tramp_image_put(tr->cur_image);
		tr->cur_image = NULL;
		tr->selector = 0;
		goto out;
	}

	im = bpf_tramp_image_alloc(tr->id, tr->selector);
	if (IS_ERR(im)) {
		err = PTR_ERR(im);
		goto out;
	}

	if (tprogs[BPF_TRAMP_FEXIT].nr_progs ||
	    tprogs[BPF_TRAMP_MODIFY_RETURN].nr_progs)
		flags = BPF_TRAMP_F_CALL_ORIG | BPF_TRAMP_F_SKIP_FRAME;

	if (ip_arg)
		flags |= BPF_TRAMP_F_IP_ARG;

	err = arch_prepare_bpf_trampoline(im, im->image, im->image + PAGE_SIZE,
					  &tr->func.model, flags, tprogs,
					  tr->id->addr[0]);
	if (err < 0)
		goto out;

	WARN_ON(tr->cur_image && tr->selector == 0);
	WARN_ON(!tr->cur_image && tr->selector);
	if (tr->cur_image)
		/* progs already running at this address */
		err = modify_fentry(tr, tr->cur_image->image, im->image);
	else
		/* first time registering */
		err = register_fentry(tr, im->image);
	if (err)
		goto out;
	if (tr->cur_image)
		bpf_tramp_image_put(tr->cur_image);
	tr->cur_image = im;
	tr->selector++;
out:
	kfree(tprogs);
	return err;
}

static enum bpf_tramp_prog_type bpf_attach_type_to_tramp(struct bpf_prog *prog)
{
	switch (prog->expected_attach_type) {
	case BPF_TRACE_FENTRY:
		return BPF_TRAMP_FENTRY;
	case BPF_MODIFY_RETURN:
		return BPF_TRAMP_MODIFY_RETURN;
	case BPF_TRACE_FEXIT:
		return BPF_TRAMP_FEXIT;
	case BPF_LSM_MAC:
		if (!prog->aux->attach_func_proto->type)
			/* The function returns void, we cannot modify its
			 * return value.
			 */
			return BPF_TRAMP_FEXIT;
		else
			return BPF_TRAMP_MODIFY_RETURN;
	default:
		return BPF_TRAMP_REPLACE;
	}
}

int bpf_trampoline_link_prog(struct bpf_tramp_node *node, struct bpf_trampoline *tr)
{
	struct bpf_prog *prog = node->prog;
	enum bpf_tramp_prog_type kind;
	int err = 0;
	int cnt;

	kind = bpf_attach_type_to_tramp(prog);
	mutex_lock(&tr->mutex);
	if (tr->extension_prog) {
		/* cannot attach fentry/fexit if extension prog is attached.
		 * cannot overwrite extension prog either.
		 */
		err = -EBUSY;
		goto out;
	}
	cnt = tr->progs_cnt[BPF_TRAMP_FENTRY] + tr->progs_cnt[BPF_TRAMP_FEXIT];
	if (kind == BPF_TRAMP_REPLACE) {
		/* Cannot attach extension if fentry/fexit are in use. */
		if (cnt) {
			err = -EBUSY;
			goto out;
		}
		tr->extension_prog = prog;
		err = bpf_arch_text_poke(tr->id->addr[0], BPF_MOD_JUMP, NULL,
					 prog->bpf_func);
		goto out;
	}
	if (cnt >= BPF_MAX_TRAMP_PROGS) {
		err = -E2BIG;
		goto out;
	}
	if (!hlist_unhashed(&node->hlist_tramp)) {
		/* prog already linked */
		err = -EBUSY;
		goto out;
	}
	hlist_add_head(&node->hlist_tramp, &tr->progs_hlist[kind]);
	tr->progs_cnt[kind]++;
	err = bpf_trampoline_update(tr);
	if (err) {
		hlist_del_init(&node->hlist_tramp);
		tr->progs_cnt[kind]--;
	}
out:
	mutex_unlock(&tr->mutex);
	return err;
}

/* bpf_trampoline_unlink_prog() should never fail. */
int bpf_trampoline_unlink_prog(struct bpf_tramp_node *node, struct bpf_trampoline *tr)
{
	struct bpf_prog *prog = node->prog;
	enum bpf_tramp_prog_type kind;
	int err;

	kind = bpf_attach_type_to_tramp(prog);
	mutex_lock(&tr->mutex);
	if (kind == BPF_TRAMP_REPLACE) {
		WARN_ON_ONCE(!tr->extension_prog);
		err = bpf_arch_text_poke(tr->id->addr[0], BPF_MOD_JUMP,
					 tr->extension_prog->bpf_func, NULL);
		tr->extension_prog = NULL;
		goto out;
	}
	hlist_del_init(&node->hlist_tramp);
	tr->progs_cnt[kind]--;
	err = bpf_trampoline_update(tr);
out:
	mutex_unlock(&tr->mutex);
	return err;
}

void bpf_trampoline_put(struct bpf_trampoline *tr)
{
	if (!tr)
		return;
	mutex_lock(&trampoline_mutex);
	if (!refcount_dec_and_test(&tr->refcnt))
		goto out;
	WARN_ON_ONCE(mutex_is_locked(&tr->mutex));
	if (WARN_ON_ONCE(!hlist_empty(&tr->progs_hlist[BPF_TRAMP_FENTRY])))
		goto out;
	if (WARN_ON_ONCE(!hlist_empty(&tr->progs_hlist[BPF_TRAMP_FEXIT])))
		goto out;
	/* This code will be executed even when the last bpf_tramp_image
	 * is alive. All progs are detached from the trampoline and the
	 * trampoline image is patched with jmp into epilogue to skip
	 * fexit progs. The fentry-only trampoline will be freed via
	 * multiple rcu callbacks.
	 */
	hlist_del(&tr->hlist);
	kfree(tr);
out:
	mutex_unlock(&trampoline_mutex);
}

static struct bpf_tramp_node *node_alloc(struct bpf_trampoline *tr, struct bpf_prog *prog)
{
	struct bpf_tramp_node *node;

	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
		return NULL;

	INIT_HLIST_NODE(&node->hlist_tramp);
	INIT_HLIST_NODE(&node->hlist_attach);
	node->prog = prog;
	node->tr = tr;
	return node;
}

static void node_free(struct bpf_tramp_node *node)
{
	bpf_trampoline_put(node->tr);
	kfree(node);
}

struct bpf_tramp_attach *bpf_tramp_attach(struct bpf_tramp_id *id,
					  struct bpf_prog *tgt_prog,
					  struct bpf_prog *prog)
{
	struct bpf_trampoline *tr = NULL;
	struct bpf_tramp_attach *attach;
	struct bpf_tramp_node *node;
	int err;

	attach = kzalloc(sizeof(*attach), GFP_KERNEL);
	if (!attach)
		return ERR_PTR(-ENOMEM);

	tr = bpf_trampoline_get(id);
	if (!tr) {
		err = -ENOMEM;
		goto out;
	}

	node = node_alloc(tr, prog);
	if (!node)
		goto out;

	err = bpf_check_attach_model(prog, tgt_prog, id->id[0], &tr->func.model);
	if (err)
		goto out;

	attach->id = id;
	hlist_add_head(&node->hlist_attach, &attach->nodes);
	return attach;

out:
	bpf_trampoline_put(tr);
	kfree(attach);
	return ERR_PTR(err);
}

void bpf_tramp_detach(struct bpf_tramp_attach *attach)
{
	struct bpf_tramp_node *node;
	struct hlist_node *n;

	hlist_for_each_entry_safe(node, n, &attach->nodes, hlist_attach)
		node_free(node);

	bpf_tramp_id_free(attach->id);
	kfree(attach);
}

int bpf_tramp_attach_link(struct bpf_tramp_attach *attach)
{
	struct bpf_tramp_node *node;
	int err;

	hlist_for_each_entry(node, &attach->nodes, hlist_attach) {
		err = bpf_trampoline_link_prog(node, node->tr);
		if (err)
			return err;
	}

	return 0;
}

int bpf_tramp_attach_unlink(struct bpf_tramp_attach *attach)
{
	struct bpf_tramp_node *node;
	int err;

	hlist_for_each_entry(node, &attach->nodes, hlist_attach) {
		err = bpf_trampoline_unlink_prog(node, node->tr);
		if (err)
			return err;
	}

	return 0;
}

#define NO_START_TIME 1
static __always_inline u64 notrace bpf_prog_start_time(void)
{
	u64 start = NO_START_TIME;

	if (static_branch_unlikely(&bpf_stats_enabled_key)) {
		start = sched_clock();
		if (unlikely(!start))
			start = NO_START_TIME;
	}
	return start;
}

static void notrace inc_misses_counter(struct bpf_prog *prog)
{
	struct bpf_prog_stats *stats;

	stats = this_cpu_ptr(prog->stats);
	u64_stats_update_begin(&stats->syncp);
	u64_stats_inc(&stats->misses);
	u64_stats_update_end(&stats->syncp);
}

/* The logic is similar to bpf_prog_run(), but with an explicit
 * rcu_read_lock() and migrate_disable() which are required
 * for the trampoline. The macro is split into
 * call __bpf_prog_enter
 * call prog->bpf_func
 * call __bpf_prog_exit
 *
 * __bpf_prog_enter returns:
 * 0 - skip execution of the bpf prog
 * 1 - execute bpf prog
 * [2..MAX_U64] - execute bpf prog and record execution time.
 *     This is start time.
 */
u64 notrace __bpf_prog_enter(struct bpf_prog *prog)
	__acquires(RCU)
{
	rcu_read_lock();
	migrate_disable();
	if (unlikely(__this_cpu_inc_return(*(prog->active)) != 1)) {
		inc_misses_counter(prog);
		return 0;
	}
	return bpf_prog_start_time();
}

static void notrace update_prog_stats(struct bpf_prog *prog,
				      u64 start)
{
	struct bpf_prog_stats *stats;

	if (static_branch_unlikely(&bpf_stats_enabled_key) &&
	    /* static_key could be enabled in __bpf_prog_enter*
	     * and disabled in __bpf_prog_exit*.
	     * And vice versa.
	     * Hence check that 'start' is valid.
	     */
	    start > NO_START_TIME) {
		unsigned long flags;

		stats = this_cpu_ptr(prog->stats);
		flags = u64_stats_update_begin_irqsave(&stats->syncp);
		u64_stats_inc(&stats->cnt);
		u64_stats_add(&stats->nsecs, sched_clock() - start);
		u64_stats_update_end_irqrestore(&stats->syncp, flags);
	}
}

void notrace __bpf_prog_exit(struct bpf_prog *prog, u64 start)
	__releases(RCU)
{
	update_prog_stats(prog, start);
	__this_cpu_dec(*(prog->active));
	migrate_enable();
	rcu_read_unlock();
}

u64 notrace __bpf_prog_enter_sleepable(struct bpf_prog *prog)
{
	rcu_read_lock_trace();
	migrate_disable();
	might_fault();
	if (unlikely(__this_cpu_inc_return(*(prog->active)) != 1)) {
		inc_misses_counter(prog);
		return 0;
	}
	return bpf_prog_start_time();
}

void notrace __bpf_prog_exit_sleepable(struct bpf_prog *prog, u64 start)
{
	update_prog_stats(prog, start);
	__this_cpu_dec(*(prog->active));
	migrate_enable();
	rcu_read_unlock_trace();
}

void notrace __bpf_tramp_enter(struct bpf_tramp_image *tr)
{
	percpu_ref_get(&tr->pcref);
}

void notrace __bpf_tramp_exit(struct bpf_tramp_image *tr)
{
	percpu_ref_put(&tr->pcref);
}

int __weak
arch_prepare_bpf_trampoline(struct bpf_tramp_image *tr, void *image, void *image_end,
			    const struct btf_func_model *m, u32 flags,
			    struct bpf_tramp_progs *tprogs,
			    void *orig_call)
{
	return -ENOTSUPP;
}

static int __init init_trampolines(void)
{
	int i;

	for (i = 0; i < TRAMPOLINE_TABLE_SIZE; i++)
		INIT_HLIST_HEAD(&trampoline_table[i]);
	return 0;
}
late_initcall(init_trampolines);
