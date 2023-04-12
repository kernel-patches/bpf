// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Meta Platforms, Inc. and affiliates. */
#include "linux/bpf.h"
#include <test_progs.h>
#include <bpf/btf.h>
#include "cap_helpers.h"
#include "lsm_map_create.skel.h"

static int drop_priv_caps(__u64 *old_caps)
{
	return cap_disable_effective((1ULL << CAP_BPF) |
				     (1ULL << CAP_PERFMON) |
				     (1ULL << CAP_NET_ADMIN) |
				     (1ULL << CAP_SYS_ADMIN), old_caps);
}

static int restore_priv_caps(__u64 old_caps)
{
	return cap_enable_effective(old_caps, NULL);
}

void test_lsm_map_create(void)
{
	struct btf *btf = NULL;
	struct lsm_map_create *skel = NULL;
	const struct btf_type *t;
	const struct btf_enum *e;
	int i, n, id, err, ret;

	skel = lsm_map_create__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		return;

	skel->bss->my_tid = syscall(SYS_gettid);
	skel->bss->decision = 0;

	err = lsm_map_create__attach(skel);
	if (!ASSERT_OK(err, "skel_attach"))
		goto cleanup;

	btf = btf__parse("/sys/kernel/btf/vmlinux", NULL);
	if (!ASSERT_OK_PTR(btf, "btf_parse"))
		goto cleanup;

	/* find enum bpf_map_type and enumerate each value */
	id = btf__find_by_name_kind(btf, "bpf_map_type", BTF_KIND_ENUM);
	if (!ASSERT_GT(id, 0, "bpf_map_type_id"))
		goto cleanup;

	t = btf__type_by_id(btf, id);
	e = btf_enum(t);
	n = btf_vlen(t);
	for (i = 0; i < n; e++, i++) {
		enum bpf_map_type map_type = (enum bpf_map_type)e->val;
		const char *map_type_name;
		__u64 orig_caps;
		bool is_map_priv;
		bool needs_btf;

		if (map_type == BPF_MAP_TYPE_UNSPEC)
			continue;

		/* this will show which map type we are working with in verbose log */
		map_type_name = btf__str_by_offset(btf, e->name_off);
		ASSERT_OK_PTR(map_type_name, map_type_name);

		switch (map_type) {
		case BPF_MAP_TYPE_ARRAY:
		case BPF_MAP_TYPE_PERCPU_ARRAY:
		case BPF_MAP_TYPE_PROG_ARRAY:
		case BPF_MAP_TYPE_PERF_EVENT_ARRAY:
		case BPF_MAP_TYPE_CGROUP_ARRAY:
		case BPF_MAP_TYPE_ARRAY_OF_MAPS:
		case BPF_MAP_TYPE_HASH:
		case BPF_MAP_TYPE_PERCPU_HASH:
		case BPF_MAP_TYPE_HASH_OF_MAPS:
		case BPF_MAP_TYPE_RINGBUF:
		case BPF_MAP_TYPE_USER_RINGBUF:
		case BPF_MAP_TYPE_CGROUP_STORAGE:
		case BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE:
			is_map_priv = false;
			needs_btf = false;
			break;
		case BPF_MAP_TYPE_SK_STORAGE:
		case BPF_MAP_TYPE_INODE_STORAGE:
		case BPF_MAP_TYPE_TASK_STORAGE:
		case BPF_MAP_TYPE_CGRP_STORAGE:
			is_map_priv = true;
			needs_btf = true;
			break;
		default:
			is_map_priv = true;
			needs_btf = false;
		}

		/* make sure we delegate to kernel for final decision */
		skel->bss->decision = 0;

		/* we are normally under sudo, so all maps should succeed */
		ret = libbpf_probe_bpf_map_type(map_type, NULL);
		ASSERT_EQ(ret, 1, "default_priv_mode");

		/* local storage needs custom BTF to be loaded, which we
		 * currently can't do once we drop privileges, so skip few
		 * checks for such maps
		 */
		if (needs_btf)
			goto skip_if_needs_btf;

		/* now let's drop privileges, and chech that unpriv maps are
		 * still possible to create
		 */
		if (!ASSERT_OK(drop_priv_caps(&orig_caps), "drop_caps"))
			goto cleanup;

		ret = libbpf_probe_bpf_map_type(map_type, NULL);
		ASSERT_EQ(ret, is_map_priv ? 0 : 1,  "default_unpriv_mode");

		/* allow any map creation for our thread */
		skel->bss->decision = 1;
		ret = libbpf_probe_bpf_map_type(map_type, NULL);
		ASSERT_EQ(ret, 1, "lsm_allow_unpriv_mode");

		/* reject any map creation for our thread */
		skel->bss->decision = -1;
		ret = libbpf_probe_bpf_map_type(map_type, NULL);
		ASSERT_EQ(ret, 0, "lsm_reject_unpriv_mode");

		/* restore privileges, but keep reject LSM policy */
		if (!ASSERT_OK(restore_priv_caps(orig_caps), "restore_caps"))
			goto cleanup;

skip_if_needs_btf:
		/* even with all caps map create will fail */
		skel->bss->decision = -1;
		ret = libbpf_probe_bpf_map_type(map_type, NULL);
		ASSERT_EQ(ret, 0, "lsm_reject_priv_mode");
	}

cleanup:
	btf__free(btf);
	lsm_map_create__destroy(skel);
}
