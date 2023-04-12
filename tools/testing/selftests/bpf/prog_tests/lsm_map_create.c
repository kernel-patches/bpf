// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Meta Platforms, Inc. and affiliates. */
#include "linux/bpf.h"
#include <test_progs.h>
#include <bpf/btf.h>
#include "cap_helpers.h"
#include "lsm_map_create.skel.h"
#include "just_maps.skel.h"

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

static void subtest_map_create_probes(void)
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
		map_type = BPF_MAP_TYPE_SK_STORAGE;

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

		/* now let's drop privileges, and chech that unpriv maps are
		 * still possible to create
		 */
		if (!ASSERT_OK(drop_priv_caps(&orig_caps), "drop_caps"))
			goto cleanup;

		ret = libbpf_probe_bpf_map_type(map_type, NULL);
		/* maps that require custom BTF will fail with -EPERM */
		if (needs_btf)
			ASSERT_EQ(ret, -EPERM, "default_unpriv_mode");
		else
			ASSERT_EQ(ret, is_map_priv ? 0 : 1,  "default_unpriv_mode");

		/* allow any map creation for our thread */
		skel->bss->decision = 1;
		ret = libbpf_probe_bpf_map_type(map_type, NULL);
		ASSERT_EQ(ret, 1, "lsm_allow_unpriv_mode");

		/* reject any map creation for our thread */
		skel->bss->decision = -1;
		ret = libbpf_probe_bpf_map_type(map_type, NULL);
		/* maps that require custom BTF will fail with -EPERM */
		if (needs_btf)
			ASSERT_EQ(ret, -EPERM, "lsm_reject_unpriv_mode");
		else
			ASSERT_EQ(ret, 0, "lsm_reject_unpriv_mode");

		/* restore privileges, but keep reject LSM policy */
		if (!ASSERT_OK(restore_priv_caps(orig_caps), "restore_caps"))
			goto cleanup;

		/* even with all caps map create will fail */
		skel->bss->decision = -1;
		ret = libbpf_probe_bpf_map_type(map_type, NULL);
		if (needs_btf)
			ASSERT_EQ(ret, -EPERM, "lsm_reject_priv_mode");
		else
			ASSERT_EQ(ret, 0, "lsm_reject_priv_mode");
	}

cleanup:
	btf__free(btf);
	lsm_map_create__destroy(skel);
}

static void subtest_map_create_obj(void)
{
	struct lsm_map_create *skel = NULL;
	struct just_maps *maps_skel = NULL;
	struct bpf_map_info map_info;
	__u32 map_info_sz = sizeof(map_info);
	__u64 orig_caps;
	int err, map_fd;

	skel = lsm_map_create__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		return;

	skel->bss->my_tid = syscall(SYS_gettid);
	skel->bss->decision = 0;

	err = lsm_map_create__attach(skel);
	if (!ASSERT_OK(err, "skel_attach"))
		goto cleanup;

	/* now let's drop privileges, and chech that unpriv maps are
	 * still possible to create and they do have BTF associated with it
	 */
	if (!ASSERT_OK(drop_priv_caps(&orig_caps), "drop_caps"))
		goto cleanup;

	/* allow unprivileged BPF map and BTF obj creation */
	skel->bss->decision = 1;

	maps_skel = just_maps__open_and_load();
	if (!ASSERT_OK_PTR(maps_skel, "maps_skel_open_and_load"))
		goto restore_caps;

	ASSERT_GT(bpf_object__btf_fd(maps_skel->obj), 0, "maps_btf_fd");

	/* check that SK_LOCAL_STORAGE map has BTF info */
	map_fd = bpf_map__fd(maps_skel->maps.sk_msg_netns_cookies);
	memset(&map_info, 0, map_info_sz);
	err = bpf_map_get_info_by_fd(map_fd, &map_info, &map_info_sz);
	ASSERT_OK(err, "get_map_info_by_fd");

	ASSERT_GT(map_info.btf_id, 0, "map_btf_id");
	ASSERT_GT(map_info.btf_key_type_id, 0, "map_btf_key_type_id");
	ASSERT_GT(map_info.btf_value_type_id, 0, "map_btf_value_type_id");

restore_caps:
	ASSERT_OK(restore_priv_caps(orig_caps), "restore_caps");
cleanup:
	just_maps__destroy(maps_skel);
	lsm_map_create__destroy(skel);
}

void test_lsm_map_create(void)
{
	if (test__start_subtest("map_create_probes"))
		subtest_map_create_probes();
	if (test__start_subtest("map_create_obj"))
		subtest_map_create_obj();
}
