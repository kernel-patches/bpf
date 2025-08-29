// SPDX-License-Identifier: GPL-2.0
/*
 * cpuidle_gov_ext.c - test to use cpuidle governor ext by bpf
 *
 * Copyright (C) Yikai Lin <yikai.lin@vivo.com>
 */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif
#ifndef max
#define max(a, b) ((a) > (b) ? (a) : (b))
#endif
#ifndef min
#define min(a, b) ((a) < (b) ? (a) : (b))
#endif

#define ALPHA 10
#define ALPHA_SCALE 100
#define FIT_FACTOR 90

/*
 * For some low-power scenarios,
 * such as the screen off scenario of mobile devices
 * (which will be determined by the user-space BPF program),
 * we aim to choose a deeper state
 * At this point, we will somewhat disregard the impact on CPU performance.
 */
int expect_deeper = 0;

int bpf_cpuidle_ext_gov_update_rating(unsigned int rating) __ksym __weak;
s64 bpf_cpuidle_ext_gov_latency_req(unsigned int cpu) __ksym __weak;
s64 bpf_tick_nohz_get_sleep_length(void) __ksym __weak;

struct cpuidle_gov_data {
	int cpu;
	int last_idx;
	u64 last_pred;
	u64 last_duration;
	u64 next_pred;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct cpuidle_gov_data);
} cpuidle_gov_data_map SEC(".maps");

static u64 calculate_ewma(u64 last, u64 new, u32 alpha, u32 alpha_scale)
{
	return (alpha * new + (alpha_scale - alpha) * last) / alpha_scale;
}

static void update_predict_duration(struct cpuidle_gov_data *data,
			struct cpuidle_driver *drv, struct cpuidle_device *dev)
{
	int idx;
	struct cpuidle_state target;

	if (!data || !drv || !dev)
		return;
	idx = data->last_idx;
	data->last_duration = dev->last_residency_ns;
	if (idx > 0) {
		bpf_core_read(&target, sizeof(target), &drv->states[idx]);
		if (data->last_duration > target.exit_latency)
			data->last_duration -= target.exit_latency;
	}
	data->last_pred = data->next_pred;
	data->next_pred = calculate_ewma(data->next_pred,
		data->last_duration, ALPHA, ALPHA_SCALE);
}

/* Enable the cpuidle governor */
SEC("struct_ops.s/enable")
int BPF_PROG(bpf_cpuidle_enable, struct cpuidle_driver *drv, struct cpuidle_device *dev)
{
	u32 key = 0;
	struct cpuidle_gov_data *data;

	bpf_printk("cpuidle_gov_ext: enabled");
	data = bpf_map_lookup_percpu_elem(&cpuidle_gov_data_map, &key, dev->cpu);
	if (!data)
		return 0;

	__builtin_memset(data, 0, sizeof(struct cpuidle_gov_data));
	data->cpu = dev->cpu;
	return 0;
}

/* Disable the cpuidle governor */
SEC("struct_ops.s/disable")
void BPF_PROG(bpf_cpuidle_disable, struct cpuidle_driver *drv, struct cpuidle_device *dev)
{
	bpf_printk("cpuidle_gov_ext: disabled");
}

/* Select the next idle state */
SEC("struct_ops.s/select")
int BPF_PROG(bpf_cpuidle_select, struct cpuidle_driver *drv, struct cpuidle_device *dev)
{
	u32 key = 0;
	s64 delta, latency_req, residency_ns;
	int i, selected;
	unsigned long long disable = 0;
	struct cpuidle_gov_data *data;
	struct cpuidle_state cs;

	data = bpf_map_lookup_percpu_elem(&cpuidle_gov_data_map, &key, dev->cpu);
	if (!data) {
		bpf_printk("cpuidle_gov_ext: [%s] cpuidle_gov_data_map is NULL\n", __func__);
		return 0;
	}
	latency_req = bpf_cpuidle_ext_gov_latency_req(dev->cpu);
	delta = bpf_tick_nohz_get_sleep_length();

	update_predict_duration(data, drv, dev);

	for (i = ARRAY_SIZE(drv->states)-1; i > 0; i--) {
		if (i > drv->state_count-1)
			continue;
		bpf_core_read(&cs, sizeof(cs), &drv->states[i]);
		bpf_core_read(&disable, sizeof(disable), &dev->states_usage[i]);

		if (disable)
			continue;

		if (latency_req < cs.exit_latency_ns)
			continue;

		if (delta < cs.target_residency_ns)
			continue;

		if (data->next_pred / FIT_FACTOR * ALPHA_SCALE < cs.target_residency_ns)
			continue;

		break;
	}
	residency_ns = drv->states[i].target_residency_ns;
	if (expect_deeper &&
		i < drv->state_count - 1 &&
		data->last_pred >= residency_ns &&
		data->next_pred < residency_ns &&
		data->next_pred / FIT_FACTOR * ALPHA_SCALE >= residency_ns &&
		data->next_pred / FIT_FACTOR * ALPHA_SCALE >= data->last_duration &&
		delta > residency_ns) {
		i++;
	}

	selected = i;
	return selected;
}

//enable or disable scheduling tick after selecting cpuidle state
SEC("struct_ops.s/set_stop_tick")
bool BPF_PROG(bpf_cpuidle_set_stop_tick)
{
	return false;
}

/* Reflect function called after entering an idle state */
SEC("struct_ops.s/reflect")
void BPF_PROG(bpf_cpuidle_reflect, struct cpuidle_device *dev, int index)
{
	u32 key = 0;
	struct cpuidle_gov_data *data;

	data = bpf_map_lookup_percpu_elem(&cpuidle_gov_data_map, &key, dev->cpu);
	if (!data) {
		bpf_printk("cpuidle_gov_ext: [%s] cpuidle_gov_data_map is NULL\n", __func__);
		return;
	}
	data->last_idx = index;
}

/* Initialize the BPF cpuidle governor */
SEC("struct_ops.s/init")
int BPF_PROG(bpf_cpuidle_init)
{
	int ret = bpf_cpuidle_ext_gov_update_rating(60);
	return ret;
}

/* Cleanup after the BPF cpuidle governor */
SEC("struct_ops.s/exit")
void BPF_PROG(bpf_cpuidle_exit) { }

/* Struct_ops linkage for cpuidle governor */
SEC(".struct_ops.link")
struct cpuidle_gov_ext_ops ops = {
	.enable  = (void *)bpf_cpuidle_enable,
	.disable = (void *)bpf_cpuidle_disable,
	.select  = (void *)bpf_cpuidle_select,
	.set_stop_tick = (void *)bpf_cpuidle_set_stop_tick,
	.reflect = (void *)bpf_cpuidle_reflect,
	.init	= (void *)bpf_cpuidle_init,
	.exit	= (void *)bpf_cpuidle_exit,
	.name	= "BPF_cpuidle_gov"
};
