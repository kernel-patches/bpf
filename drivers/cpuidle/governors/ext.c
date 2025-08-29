// SPDX-License-Identifier: GPL-2.0
/*
 * ext.c - the cpuidle ext governor used by BPF
 *
 * Copyright (C) Yikai Lin <yikai.lin@vivo.com>
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/cpuidle.h>
#include <linux/percpu.h>
#include <linux/ktime.h>
#include <linux/cpumask.h>
#include <linux/slab.h>
#include <linux/sysfs.h>
#include <linux/tick.h>

#define EXT_GOV_NAME	"ext"

/********************************************************************************
 * Helpers that can be called from the BPF cpuidle gov.
 */
#include <linux/btf_ids.h>
#include <linux/btf.h>

#include "../cpuidle.h"

static struct cpuidle_governor *cpuidle_last_governor;

/**
 * restore_cpuidle_last_governor - restore last governor after bpf ext gov exiting.
 */
static void restore_cpuidle_last_governor(void)
{
	bool enabled = false;

	if (cpuidle_curr_governor)
		enabled = !strncasecmp(cpuidle_curr_governor->name, EXT_GOV_NAME, CPUIDLE_NAME_LEN);

	mutex_lock(&cpuidle_lock);
	if (enabled && cpuidle_last_governor)
		if (cpuidle_switch_governor(cpuidle_last_governor))
			cpuidle_last_governor = NULL;
	mutex_unlock(&cpuidle_lock);
}

__bpf_kfunc_start_defs();

/**
 * bpf_cpuidle_ext_gov_update_rating - update rating of bpf cpuidle ext governor.
 * @rating: target rating
 *
 * The BPF cpuidle ext governor is registered by default
 * but remains inactive due to its default @rating being set to 1
 * which is significantly lower than that of other governors.
 *
 * To activate it, adjust @rating to a higher value within the BPF program.
 *
 * This function should be called from ops.init().
 */
__bpf_kfunc int bpf_cpuidle_ext_gov_update_rating(unsigned int rating)
{
	int ret = -EINVAL;
	struct cpuidle_governor *ext_gov;

	ext_gov = cpuidle_find_governor(EXT_GOV_NAME);
	if (!ext_gov) {
		ret = -EEXIST;
		goto clean_up;
	}
	mutex_lock(&cpuidle_lock);
	if (!cpuidle_curr_governor || cpuidle_curr_governor->rating < rating) {
		cpuidle_last_governor = cpuidle_curr_governor;
		ret = cpuidle_switch_governor(ext_gov);
	}
	mutex_unlock(&cpuidle_lock);

clean_up:
	return ret;
}

/**
 * bpf_cpuidle_ext_gov_latency_req - get target cpu's latency constraint
 * @cpu: Target CPU
 *
 * The BPF program may require this info.
 */
__bpf_kfunc s64 bpf_cpuidle_ext_gov_latency_req(unsigned int cpu)
{
	return cpuidle_governor_latency_req(cpu);
}

/**
 * bpf_tick_nohz_get_sleep_length - return the expected length of the current sleep
 *
 * The BPF program may require this info.
 */
__bpf_kfunc s64 bpf_tick_nohz_get_sleep_length(void)
{
	ktime_t delta_tick;

	return (s64)tick_nohz_get_sleep_length(&delta_tick);
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(cpuidle_ext_gov_kfuncs)
BTF_ID_FLAGS(func, bpf_cpuidle_ext_gov_update_rating)
BTF_ID_FLAGS(func, bpf_cpuidle_ext_gov_latency_req)
BTF_ID_FLAGS(func, bpf_tick_nohz_get_sleep_length)
BTF_KFUNCS_END(cpuidle_ext_gov_kfuncs)

static const struct btf_kfunc_id_set cpuidle_ext_gov_kfuncs_set = {
	.owner  = THIS_MODULE,
	.set	= &cpuidle_ext_gov_kfuncs,
};

static int cpuidle_gov_kfuncs_init(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS, &cpuidle_ext_gov_kfuncs_set);
}

/********************************************************************************
 * bpf_struct_ops plumbing.
 */
#include <linux/bpf_verifier.h>
#include <linux/bpf.h>

#define CPUIDLE_GOV_EXT_NAME_LEN 128
enum ops_enable_state {
	OPS_ENABLED,
	OPS_DISABLED,
};

static const struct btf_type *cpuidle_device_type;
static u32 cpuidle_device_type_id;
static struct cpuidle_gov_ext_ops *ops;

static DEFINE_MUTEX(ops_mutex);
DEFINE_STATIC_KEY_FALSE(ops_enabled_key);
static atomic_t ops_enable_state_var = ATOMIC_INIT(OPS_DISABLED);

struct cpuidle_gov_ext_ops {
	/**
	 * enable - cpuidle ext governor enable
	 * @drv: cpuidle driver containing state data.
	 * @dev: target cpu
	 */
	int (*enable)(struct cpuidle_driver *drv, struct cpuidle_device *dev);

	/**
	 * disable - cpuidle ext governor disable
	 * @drv: cpuidle driver containing state data.
	 * @dev: target cpu
	 */
	void (*disable)(struct cpuidle_driver *drv, struct cpuidle_device *dev);

	/*
	 * select - select the next cpu idle state to enter
	 * @drv: cpuidle driver containing state data.
	 * @dev: target cpu
	 */
	int (*select)(struct cpuidle_driver *drv, struct cpuidle_device *dev);

	/*
	 * set_stop_tick - whether or not to stop the scheduler tick
	 * automatically called after selecting cpuidle state
	 */
	bool (*set_stop_tick)(void);

	/*
	 * reflect - Give the governor an opportunity to reflect on the outcome
	 * @dev: target cpu
	 * @index: last idle state which target cpu has entered
	 */
	void (*reflect)(struct cpuidle_device *dev, int index);

	/**
	 * init - Initialize the BPF cpuidle governor
	 */
	int (*init)(void);

	/**
	 * exit - Clean up after the BPF cpuidle governor
	 */
	void (*exit)(void);

	/**
	 * name - BPF cpuidle governor name
	 */
	char name[CPUIDLE_GOV_EXT_NAME_LEN];
};

static enum ops_enable_state get_ops_enable_state(void)
{
	return atomic_read(&ops_enable_state_var);
}

static enum ops_enable_state
set_ops_enable_state(enum ops_enable_state to)
{
	return atomic_xchg(&ops_enable_state_var, to);
}

static int enable_stub(struct cpuidle_driver *drv, struct cpuidle_device *dev) { return 0; }
static void disable_stub(struct cpuidle_driver *drv, struct cpuidle_device *dev) {}
static int select_stub(struct cpuidle_driver *drv, struct cpuidle_device *dev) { return 0; }
static bool set_stop_tick_stub(void) {return false; }
static void reflect_stub(struct cpuidle_device *dev, int index) {}
static int init_stub(void) { return 0; }
static void exit_stub(void) {}

static struct cpuidle_gov_ext_ops __bpf_ops_cpuidle_gov_ext_ops = {
	.enable = enable_stub,
	.disable = disable_stub,
	.select = select_stub,
	.set_stop_tick = set_stop_tick_stub,
	.reflect = reflect_stub,
	.init = init_stub,
	.exit = exit_stub,
};

static int ext_btf_struct_access(struct bpf_verifier_log *log,
					 const struct bpf_reg_state *reg, int off,
					 int size)
{
	const struct btf_type *t;

	t = btf_type_by_id(reg->btf, reg->btf_id);
	if (t == cpuidle_device_type) {
		for (int i = 0; i < CPUIDLE_STATE_MAX; i++) {
			size_t base_offset = offsetof(struct cpuidle_device, states_usage[i]);

			if (off >= base_offset + offsetof(struct cpuidle_state_usage, disable) &&
				off + size <= base_offset + offsetofend(struct cpuidle_state_usage, disable)) {
				return SCALAR_VALUE;
			}
		}
	}

	return -EACCES;
}

static const struct bpf_verifier_ops ops_verifier = {
	.get_func_proto = bpf_base_func_proto,
	.is_valid_access = btf_ctx_access,
	.btf_struct_access = ext_btf_struct_access,
};

static void ops_disable(void)
{
	restore_cpuidle_last_governor();
	WARN_ON_ONCE(set_ops_enable_state(OPS_DISABLED) != OPS_ENABLED);
	static_branch_disable(&ops_enabled_key);
	if (ops->exit)
		ops->exit();
	memset(&ops, 0, sizeof(ops));
}

static void ops_unreg(void *kdata, struct bpf_link *link)
{
	mutex_lock(&ops_mutex);
	ops_disable();
	mutex_unlock(&ops_mutex);
}

static int ops_reg(void *kdata, struct bpf_link *link)
{
	mutex_lock(&ops_mutex);
	if (get_ops_enable_state() != OPS_DISABLED) {
		mutex_unlock(&ops_mutex);
		return -EEXIST;
	}
	/*
	 * Set ops, call ops.init(), and set enable state flag
	 */
	ops = (struct cpuidle_gov_ext_ops *)kdata;
	if (ops->init && ops->init()) {
		ops_disable();
		mutex_unlock(&ops_mutex);
		return -EINVAL;
	}
	WARN_ON_ONCE(set_ops_enable_state(OPS_ENABLED) != OPS_DISABLED);
	static_branch_enable(&ops_enabled_key);

	mutex_unlock(&ops_mutex);
	return 0;
}

static int ops_check_member(const struct btf_type *t,
				const struct btf_member *member,
				const struct bpf_prog *prog)
{
	u32 moff = __btf_member_bit_offset(t, member) / 8;

	switch (moff) {
	case offsetof(struct cpuidle_gov_ext_ops, enable):
	case offsetof(struct cpuidle_gov_ext_ops, disable):
	case offsetof(struct cpuidle_gov_ext_ops, select):
	case offsetof(struct cpuidle_gov_ext_ops, set_stop_tick):
	case offsetof(struct cpuidle_gov_ext_ops, reflect):
	case offsetof(struct cpuidle_gov_ext_ops, init):
	case offsetof(struct cpuidle_gov_ext_ops, exit):
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static int ops_init_member(const struct btf_type *t,
				const struct btf_member *member,
				void *kdata, const void *udata)
{
	const struct cpuidle_gov_ext_ops *uops = udata;
	struct cpuidle_gov_ext_ops *ops = kdata;
	u32 moff = __btf_member_bit_offset(t, member) / 8;
	int ret;

	switch (moff) {
	case offsetof(struct cpuidle_gov_ext_ops, name):
		ret = bpf_obj_name_cpy(ops->name, uops->name,
				sizeof(ops->name));
		if (ret < 0)
			return ret;
		if (ret == 0)
			return -EINVAL;
		return 1;
	}
	return 0;
}

static int ops_init(struct btf *btf)
{
	s32 type_id;

	type_id = btf_find_by_name_kind(btf, "cpuidle_device", BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	cpuidle_device_type = btf_type_by_id(btf, type_id);
	cpuidle_device_type_id = type_id;

	return 0;
}

static int ops_update(void *kdata, void *old_kdata, struct bpf_link *link)
{
	/*
	 * Not support updating the actively-loaded BPF cpuidle governor
	 */
	return -EOPNOTSUPP;
}

static int ops_validate(void *kdata)
{
	return 0;
}

static struct bpf_struct_ops bpf_cpuidle_gov_ext_ops = {
	.verifier_ops = &ops_verifier,
	.reg = ops_reg,
	.unreg = ops_unreg,
	.check_member = ops_check_member,
	.init_member = ops_init_member,
	.init = ops_init,
	.update = ops_update,
	.validate = ops_validate,
	.name = "cpuidle_gov_ext_ops",
	.owner = THIS_MODULE,
	.cfi_stubs = &__bpf_ops_cpuidle_gov_ext_ops
};

/********************************************************************************
 * default cpuidle ext governor implementations
 */
#define ALPHA_SCALE 100
#define FIT_FACTOR 90

struct cpuidle_gov_ext {
	int cpu;
	int last_idx;
	u64 last_duration;
	u64 next_pred;
};

DEFINE_PER_CPU(struct cpuidle_gov_ext, cpuidle_gov_ext_data);

static void update_predict_duration(struct cpuidle_gov_ext *data,
			struct cpuidle_driver *drv, struct cpuidle_device *dev)
{
	int idx;
	struct cpuidle_state *target;

	if (!data || !drv || !dev)
		return;
	idx = data->last_idx;
	data->last_duration = dev->last_residency_ns;
	if (idx > 0) {
		target = &drv->states[idx];
		if (data->last_duration > target->exit_latency)
			data->last_duration -= target->exit_latency;
	}
	data->next_pred = data->last_duration;
}

static void ext_reflect_dfl(struct cpuidle_device *dev, int index)
{
	struct cpuidle_gov_ext *data = this_cpu_ptr(&cpuidle_gov_ext_data);

	if (!data)
		return;
	data->last_idx = index;
}

static int ext_select_dfl(struct cpuidle_driver *drv, struct cpuidle_device *dev,
				bool *stop_tick)
{
	int i, selected;
	struct cpuidle_gov_ext *data;
	ktime_t delta_tick;
	s64 delta = tick_nohz_get_sleep_length(&delta_tick);
	s64 latency_req = cpuidle_governor_latency_req(dev->cpu);

	data = this_cpu_ptr(&cpuidle_gov_ext_data);
	if (!data)
		return 0;

	/*
	 * We aim to achieve function redefinition through BPF ops.select(),
	 * so we do not use complex algorithm here.
	 */
	update_predict_duration(data, drv, dev);
	for (i = drv->state_count - 1; i > 0; i--) {
		struct cpuidle_state *s = &drv->states[i];
		struct cpuidle_state_usage *su = &dev->states_usage[i];

		if (su->disable)
			continue;

		if (latency_req < s->exit_latency_ns)
			continue;

		if (delta < s->target_residency_ns)
			continue;

		if (data->next_pred / FIT_FACTOR * ALPHA_SCALE < s->target_residency_ns)
			continue;
		break;
	}
	selected = i;
	return selected;
}

static int ext_enable_dfl(struct cpuidle_driver *drv, struct cpuidle_device *dev)
{
	struct cpuidle_gov_ext *data = &per_cpu(cpuidle_gov_ext_data, dev->cpu);

	memset(data, 0, sizeof(struct cpuidle_gov_ext));
	data->cpu = dev->cpu;
	return 0;
}

static void ext_disable_dfl(struct cpuidle_driver *drv, struct cpuidle_device *dev) { }

/********************************************************************************
 * Register and init cpuidle governor
 */
static int ext_enable(struct cpuidle_driver *drv, struct cpuidle_device *dev)
{
	if (static_branch_likely(&ops_enabled_key))
		return ops->enable(drv, dev);
	return ext_enable_dfl(drv, dev);
}

static void ext_disable(struct cpuidle_driver *drv, struct cpuidle_device *dev)
{
	if (static_branch_likely(&ops_enabled_key))
		return ops->disable(drv, dev);
	return ext_disable_dfl(drv, dev);
}

static int ext_select(struct cpuidle_driver *drv, struct cpuidle_device *dev,
			   bool *stop_tick)
{
	int state = 0;

	if (static_branch_likely(&ops_enabled_key)) {
		state = ops->select(drv, dev);
		*stop_tick = ops->set_stop_tick();
	} else {
		state = ext_select_dfl(drv, dev, stop_tick);
	}
	return state;
}

static void ext_reflect(struct cpuidle_device *dev, int index)
{
	if (static_branch_likely(&ops_enabled_key))
		ops->reflect(dev, index);
	ext_reflect_dfl(dev, index);
}

static struct cpuidle_governor ext_governor = {
	.name = EXT_GOV_NAME,
	.rating =	1,
	.enable =	ext_enable,
	.disable = ext_disable,
	.select =	ext_select,
	.reflect =	ext_reflect,
};

static int __init init_ext(void)
{
	int ret;

	ret = cpuidle_register_governor(&ext_governor);
	if (ret)
		return ret;

	ret = register_bpf_struct_ops(&bpf_cpuidle_gov_ext_ops, cpuidle_gov_ext_ops);
	if (ret) {
		pr_err("bpf_cpuidle_gov_ext_ops register fail: %d\n", ret);
		return ret;
	}

	ret = cpuidle_gov_kfuncs_init();
	if (ret) {
		pr_err("bpf cpuidle_gov_kfuncs_init register fail: %d\n", ret);
		return ret;
	}

	return ret;
}

postcore_initcall(init_ext);
MODULE_LICENSE("GPL");
