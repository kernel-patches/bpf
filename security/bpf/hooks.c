// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2020 Google LLC.
 */
#include <linux/lsm_hooks.h>
#include <linux/bpf_lsm.h>

static struct security_hook_list bpf_lsm_hooks[] __lsm_ro_after_init = {
	#define LSM_HOOK(RET, DEFAULT, NAME, ...) \
	LSM_HOOK_INIT_DISABLED(NAME, bpf_lsm_##NAME),
	#include <linux/lsm_hook_defs.h>
	#undef LSM_HOOK
	LSM_HOOK_INIT(inode_free_security, bpf_inode_storage_free),
	LSM_HOOK_INIT(task_free, bpf_task_storage_free),
};

static int __init bpf_lsm_init(void)
{
	security_add_hooks(bpf_lsm_hooks, ARRAY_SIZE(bpf_lsm_hooks), "bpf");
	pr_info("LSM support for eBPF active\n");
	return 0;
}

struct lsm_blob_sizes bpf_lsm_blob_sizes __lsm_ro_after_init = {
	.lbs_inode = sizeof(struct bpf_storage_blob),
	.lbs_task = sizeof(struct bpf_storage_blob),
};

DEFINE_LSM(bpf) = {
	.name = "bpf",
	.init = bpf_lsm_init,
	.blobs = &bpf_lsm_blob_sizes
};

void bpf_lsm_toggle_hook(void *addr, bool value)
{
	struct security_hook_list *h;
	struct lsm_static_call *scalls;
	int i, j;

	for (i = 0; i < ARRAY_SIZE(bpf_lsm_hooks); i++) {
		h = &bpf_lsm_hooks[i];
		scalls = h->scalls;
		if (h->hook.lsm_callback == addr)
			continue;

		for (j = 0; j < MAX_LSM_COUNT; j++) {
			if (scalls[j].hl != h)
				continue;

			if (value)
				static_key_enable(scalls[j].enabled_key);
			else
				static_key_disable(scalls[j].enabled_key);
		}
	}
}
