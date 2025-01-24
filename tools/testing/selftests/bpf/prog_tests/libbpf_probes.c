/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2021 Facebook */

#include <test_progs.h>
#include <bpf/btf.h>

void test_libbpf_probe_prog_types(void)
{
	struct btf *btf;
	const struct btf_type *t;
	const struct btf_enum *e;
	int i, n, id;

	btf = btf__parse("/sys/kernel/btf/vmlinux", NULL);
	if (!ASSERT_OK_PTR(btf, "btf_parse"))
		return;

	/* find enum bpf_prog_type and enumerate each value */
	id = btf__find_by_name_kind(btf, "bpf_prog_type", BTF_KIND_ENUM);
	if (!ASSERT_GT(id, 0, "bpf_prog_type_id"))
		goto cleanup;
	t = btf__type_by_id(btf, id);
	if (!ASSERT_OK_PTR(t, "bpf_prog_type_enum"))
		goto cleanup;

	for (e = btf_enum(t), i = 0, n = btf_vlen(t); i < n; e++, i++) {
		const char *prog_type_name = btf__str_by_offset(btf, e->name_off);
		enum bpf_prog_type prog_type = (enum bpf_prog_type)e->val;
		int res;

		if (prog_type == BPF_PROG_TYPE_UNSPEC)
			continue;
		if (strcmp(prog_type_name, "__MAX_BPF_PROG_TYPE") == 0)
			continue;

		if (!test__start_subtest(prog_type_name))
			continue;

		res = libbpf_probe_bpf_prog_type(prog_type, NULL);
		ASSERT_EQ(res, 1, prog_type_name);
	}

cleanup:
	btf__free(btf);
}

void test_libbpf_probe_map_types(void)
{
	struct btf *btf;
	const struct btf_type *t;
	const struct btf_enum *e;
	int i, n, id;

	btf = btf__parse("/sys/kernel/btf/vmlinux", NULL);
	if (!ASSERT_OK_PTR(btf, "btf_parse"))
		return;

	/* find enum bpf_map_type and enumerate each value */
	id = btf__find_by_name_kind(btf, "bpf_map_type", BTF_KIND_ENUM);
	if (!ASSERT_GT(id, 0, "bpf_map_type_id"))
		goto cleanup;
	t = btf__type_by_id(btf, id);
	if (!ASSERT_OK_PTR(t, "bpf_map_type_enum"))
		goto cleanup;

	for (e = btf_enum(t), i = 0, n = btf_vlen(t); i < n; e++, i++) {
		const char *map_type_name = btf__str_by_offset(btf, e->name_off);
		enum bpf_map_type map_type = (enum bpf_map_type)e->val;
		int res;

		if (map_type == BPF_MAP_TYPE_UNSPEC)
			continue;
		if (strcmp(map_type_name, "__MAX_BPF_MAP_TYPE") == 0)
			continue;

		if (!test__start_subtest(map_type_name))
			continue;

		res = libbpf_probe_bpf_map_type(map_type, NULL);
		ASSERT_EQ(res, 1, map_type_name);
	}

cleanup:
	btf__free(btf);
}

void test_libbpf_probe_helpers(void)
{
#define CASE(prog, helper, supp) {			\
	.prog_type_name = "BPF_PROG_TYPE_" # prog,	\
	.helper_name = "bpf_" # helper,			\
	.prog_type = BPF_PROG_TYPE_ ## prog,		\
	.helper_id = BPF_FUNC_ ## helper,		\
	.supported = supp,				\
}
	const struct case_def {
		const char *prog_type_name;
		const char *helper_name;
		enum bpf_prog_type prog_type;
		enum bpf_func_id helper_id;
		bool supported;
	} cases[] = {
		CASE(KPROBE, unspec, false),
		CASE(KPROBE, map_lookup_elem, true),
		CASE(KPROBE, loop, true),

		CASE(KPROBE, ktime_get_coarse_ns, false),
		CASE(SOCKET_FILTER, ktime_get_coarse_ns, true),

		CASE(KPROBE, sys_bpf, false),
		CASE(SYSCALL, sys_bpf, true),
	};
	size_t case_cnt = ARRAY_SIZE(cases), i;
	char buf[128];

	for (i = 0; i < case_cnt; i++) {
		const struct case_def *d = &cases[i];
		int res;

		snprintf(buf, sizeof(buf), "%s+%s", d->prog_type_name, d->helper_name);

		if (!test__start_subtest(buf))
			continue;

		res = libbpf_probe_bpf_helper(d->prog_type, d->helper_id, NULL);
		ASSERT_EQ(res, d->supported, buf);
	}
}

void test_libbpf_probe_kfuncs(void)
{
	int ret, kfunc_id;
	char *kfunc = "bpf_cpumask_create";
	struct btf *btf;

	btf = btf__parse("/sys/kernel/btf/vmlinux", NULL);
	if (!ASSERT_OK_PTR(btf, "btf_parse"))
		return;

	kfunc_id = btf__find_by_name_kind(btf, kfunc, BTF_KIND_FUNC);
	if (!ASSERT_GT(kfunc_id, 0, kfunc))
		goto cleanup;

	/* prog BPF_PROG_TYPE_SYSCALL supports kfunc bpf_cpumask_create */
	ret = libbpf_probe_bpf_kfunc(BPF_PROG_TYPE_SYSCALL, kfunc_id, 0, NULL);
	ASSERT_EQ(ret, 1, kfunc);

	/* prog BPF_PROG_TYPE_KPROBE does not support kfunc bpf_cpumask_create */
	ret = libbpf_probe_bpf_kfunc(BPF_PROG_TYPE_KPROBE, kfunc_id, 0, NULL);
	ASSERT_EQ(ret, 0, kfunc);

	/* invalid kfunc id */
	ret = libbpf_probe_bpf_kfunc(BPF_PROG_TYPE_KPROBE, -1, 0, NULL);
	ASSERT_EQ(ret, 0, "invalid kfunc id:-1");

	/* invalid prog type */
	ret = libbpf_probe_bpf_kfunc(100000, kfunc_id, 0, NULL);
	if (!ASSERT_LE(ret, 0, "invalid prog type:100000"))
		goto cleanup;

cleanup:
	btf__free(btf);
}
