// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2021 Google */

#include <linux/filter.h>
#include <linux/bpf.h>

struct bpf_map_trace_target_info {
	struct list_head list;
	const struct bpf_map_trace_reg *reg_info;
	u32 btf_id;
};

static struct list_head targets = LIST_HEAD_INIT(targets);
static DEFINE_MUTEX(targets_mutex);

int bpf_map_trace_reg_target(const struct bpf_map_trace_reg *reg_info)
{
	struct bpf_map_trace_target_info *tinfo;

	tinfo = kmalloc(sizeof(*tinfo), GFP_KERNEL);
	if (!tinfo)
		return -ENOMEM;

	INIT_LIST_HEAD(&tinfo->list);
	tinfo->reg_info = reg_info;
	tinfo->btf_id = 0;

	mutex_lock(&targets_mutex);
	list_add(&tinfo->list, &targets);
	mutex_unlock(&targets_mutex);

	return 0;
}

bool bpf_map_trace_prog_supported(struct bpf_prog *prog)
{
	const char *attach_fname = prog->aux->attach_func_name;
	u32 prog_btf_id = prog->aux->attach_btf_id;
	struct bpf_map_trace_target_info *tinfo;
	bool supported = false;

	mutex_lock(&targets_mutex);
	list_for_each_entry(tinfo, &targets, list) {
		if (tinfo->btf_id && tinfo->btf_id == prog_btf_id) {
			supported = true;
			break;
		}
		if (!strcmp(attach_fname, tinfo->reg_info->target)) {
			tinfo->btf_id = prog->aux->attach_btf_id;
			supported = true;
			break;
		}
	}
	mutex_unlock(&targets_mutex);

	return supported;
}

