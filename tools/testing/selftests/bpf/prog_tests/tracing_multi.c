// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>

#ifdef __x86_64__
#include <bpf/btf.h>
#include <linux/btf.h>
#include <search.h>
#include <bpf/btf.h>
#include <linux/btf.h>
#include <search.h>
#include "tracing_multi_fentry_test.skel.h"
#include "trace_helpers.h"
#include "bpf/libbpf_internal.h"

static void multi_fentry_test(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	struct tracing_multi_fentry_test *skel = NULL;
	int err, prog_fd;

	skel = tracing_multi_fentry_test__open_and_load();
	if (!ASSERT_OK_PTR(skel, "fentry_multi_skel_load"))
		goto cleanup;

	err = tracing_multi_fentry_test__attach(skel);
	if (!ASSERT_OK(err, "fentry_attach"))
		goto cleanup;

	prog_fd = bpf_program__fd(skel->progs.test);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_run");

	ASSERT_EQ(skel->bss->test_result_1, 8, "test_result");

cleanup:
	tracing_multi_fentry_test__destroy(skel);
}

static int compare(const void *pa, const void *pb)
{
	return strcmp((char *) pa, (char *) pb);
}

static __u32 *get_ids(const char *funcs[], int funcs_cnt)
{
	size_t cap = 0, cnt = 0;
	__u32 nr, type_id;
	void *root = NULL;
	__u32 *ids = NULL;
	struct btf *btf;
	int i, err = -1;

	btf = btf__load_vmlinux_btf();
	if (!ASSERT_OK_PTR(btf, "btf__load_vmlinux_btf"))
		return NULL;

	for (i = 0; i < funcs_cnt; i++)
		tsearch(funcs[i], &root, compare);

	nr = btf__type_cnt(btf);
	for (type_id = 1; type_id < nr; type_id++) {
		const struct btf_type *type;
		const char *str;

		type = btf__type_by_id(btf, type_id);
		if (!type) {
			err = -1;
			break;
		}

		if (BTF_INFO_KIND(type->info) != BTF_KIND_FUNC)
			continue;

		str = btf__name_by_offset(btf, type->name_off);
		if (!str) {
			err = -1;
			break;
		}

		if (!tfind(str, &root, compare))
			continue;

		err = libbpf_ensure_mem((void **) &ids, &cap, sizeof(*ids), cnt + 1);
		if (err)
			break;

		ids[cnt++] = type_id;
	}

	if (err)
		free(ids);
	btf__free(btf);
	return ids;
}

static void multi_fentry_intersected_test(void)
{
	struct tracing_multi_fentry_test *skel = NULL;
	LIBBPF_OPTS(bpf_tracing_multi_opts, opts);
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	const char *funcs_1[] = {
		"bpf_fentry_test1",
		"bpf_fentry_test2",
		"bpf_fentry_test3",
		"bpf_fentry_test4",
		"bpf_fentry_test5",
	};
	const char *funcs_2[] = {
		"bpf_fentry_test4",
		"bpf_fentry_test5",
		"bpf_fentry_test6",
		"bpf_fentry_test7",
		"bpf_fentry_test8",
	};
	__u32 *ids_1 = NULL, *ids_2 = NULL;
	size_t cnt_1 = ARRAY_SIZE(funcs_1);
	size_t cnt_2 = ARRAY_SIZE(funcs_2);
	struct bpf_link *link_1 = NULL;
	struct bpf_link *link_2 = NULL;
	int err, prog_fd;

	skel = tracing_multi_fentry_test__open_and_load();
	if (!ASSERT_OK_PTR(skel, "fentry_multi_skel_load"))
		goto cleanup;

	ids_1 = get_ids(funcs_1, cnt_1);
	if (!ASSERT_OK_PTR(ids_1, "get_ids"))
		goto cleanup;
	ids_2 = get_ids(funcs_2, cnt_2);
	if (!ASSERT_OK_PTR(ids_2, "get_ids"))
		goto cleanup;

	opts.btf_ids = ids_1;
	opts.cnt = cnt_1;

	link_1 = bpf_program__attach_tracing_multi(skel->progs.test_1, NULL, &opts);
	if (!ASSERT_OK_PTR(link_1, "bpf_program__attach_tracing_multi"))
		goto cleanup;

	opts.btf_ids = ids_2;
	opts.cnt = cnt_2;

	link_2 = bpf_program__attach_tracing_multi(skel->progs.test_2, NULL, &opts);
	if (!ASSERT_OK_PTR(link_2, "bpf_program__attach_tracing_multi"))
		goto cleanup;

	prog_fd = bpf_program__fd(skel->progs.test);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_run");

	ASSERT_EQ(skel->bss->test_result_2, 5, "test_result");
	ASSERT_EQ(skel->bss->test_result_3, 5, "test_result");

cleanup:
	free(ids_1);
	free(ids_2);
	bpf_link__destroy(link_1);
	bpf_link__destroy(link_2);
	tracing_multi_fentry_test__destroy(skel);
}

static bool skip_entry(char *name)
{
	/*
	 * We attach to almost all kernel functions and some of them
	 * will cause 'suspicious RCU usage' when fprobe is attached
	 * to them. Filter out the current culprits - arch_cpu_idle
	 * default_idle and rcu_* functions.
	 */
	if (!strcmp(name, "arch_cpu_idle"))
		return true;
	if (!strcmp(name, "default_idle"))
		return true;
	if (!strncmp(name, "rcu_", 4))
		return true;
	if (!strcmp(name, "bpf_dispatcher_xdp_func"))
		return true;
	if (!strncmp(name, "__ftrace_invalid_address__",
		     sizeof("__ftrace_invalid_address__") - 1))
		return true;
	return false;
}

#define MAX_BPF_FUNC_ARGS 12

static bool btf_type_is_modifier(const struct btf_type *t)
{
	switch (BTF_INFO_KIND(t->info)) {
	case BTF_KIND_TYPEDEF:
	case BTF_KIND_VOLATILE:
	case BTF_KIND_CONST:
	case BTF_KIND_RESTRICT:
	case BTF_KIND_TYPE_TAG:
		return true;
	}
	return false;
}

static bool is_allowed_func(const struct btf *btf, const struct btf_type *t)
{
	const struct btf_type *proto;
	const struct btf_param *args;
	__u32 i, nargs;
	__s64 ret;

	proto = btf_type_by_id(btf, t->type);
	if (BTF_INFO_KIND(proto->info) != BTF_KIND_FUNC_PROTO)
		return false;

	args = (const struct btf_param *)(proto + 1);
	nargs = btf_vlen(proto);
	if (nargs > MAX_BPF_FUNC_ARGS)
		return false;

	t = btf__type_by_id(btf, proto->type);
        while (t && btf_type_is_modifier(t))
		t = btf__type_by_id(btf, t->type);

	if (btf_is_struct(t))
		return false;

	for (i = 0; i < nargs; i++) {
		/* No support for variable args */
		if (i == nargs - 1 && args[i].type == 0)
			return false;

		/* No support of struct argument size greater than 16 bytes */
		ret = btf__resolve_size(btf, args[i].type);
		if (ret < 0 || ret > 16)
			return false;
	}

	return true;
}

static void multi_fentry_bench_test(void)
{
	struct tracing_multi_fentry_test *skel = NULL;
	long attach_start_ns, attach_end_ns;
	long detach_start_ns, detach_end_ns;
	double attach_delta, detach_delta;
	struct bpf_link *link = NULL;
	size_t i, syms_cnt;
	char **syms;
	void *root = NULL;
	__u32 nr, type_id;
	struct btf *btf;
	__u32 *ids = NULL;
	size_t cap = 0, cnt = 0;
	int err;
	LIBBPF_OPTS(bpf_tracing_multi_opts, opts);

	btf = btf__load_vmlinux_btf();
	if (!ASSERT_OK_PTR(btf, "btf__load_vmlinux_btf"))
		return;

	skel = tracing_multi_fentry_test__open_and_load();
	if (!ASSERT_OK_PTR(skel, "fentry_multi_skel_load"))
		goto cleanup;

	if (!ASSERT_OK(bpf_get_ksyms(&syms, &syms_cnt, true), "get_syms"))
		goto cleanup;

	for (i = 0; i < syms_cnt; i++) {
		if (strstr(syms[i], "rcu"))
			continue;
		if (strstr(syms[i], "trace"))
			continue;
		if (strstr(syms[i], "irq"))
			continue;
		if (strstr(syms[i], "bpf_lsm_"))
			continue;
		if (!strcmp("migrate_enable", syms[i]))
			continue;
		if (!strcmp("migrate_disable", syms[i]))
			continue;
		if (!strcmp("__bpf_prog_enter_recur", syms[i]))
			continue;
		if (!strcmp("__bpf_prog_exit_recur", syms[i]))
			continue;
		if (!strcmp("preempt_count_sub", syms[i]))
			continue;
		if (!strcmp("preempt_count_add", syms[i]))
			continue;
		if (skip_entry(syms[i]))
			continue;
		tsearch(syms[i], &root, compare);
	}

	nr = btf__type_cnt(btf);
	for (type_id = 1; type_id < nr && cnt < 20000; type_id++) {
		const struct btf_type *type;
		const char *str;

		type = btf__type_by_id(btf, type_id);
		if (!type)
			break;

		if (BTF_INFO_KIND(type->info) != BTF_KIND_FUNC)
			continue;

		str = btf__name_by_offset(btf, type->name_off);
		if (!str)
			break;

		if (!tfind(str, &root, compare))
			continue;

		if (!is_allowed_func(btf, type))
			continue;

		err = libbpf_ensure_mem((void **) &ids, &cap, sizeof(*ids), cnt + 1);
		if (err)
			break;

		ids[cnt++] = type_id;
	}

	opts.btf_ids = ids;
	opts.cnt = cnt;

	attach_start_ns = get_time_ns();
	link = bpf_program__attach_tracing_multi(skel->progs.bench, NULL, &opts);
	attach_end_ns = get_time_ns();
	if (!ASSERT_OK_PTR(link, "bpf_program__attach_tracing_multi"))
		goto cleanup;

	detach_start_ns = get_time_ns();
	bpf_link__destroy(link);
	detach_end_ns = get_time_ns();

	attach_delta = (attach_end_ns - attach_start_ns) / 1000000000.0;
	detach_delta = (detach_end_ns - detach_start_ns) / 1000000000.0;

	printf("%s: found %lu functions\n", __func__, cnt);
	printf("%s: attached in %7.3lfs\n", __func__, attach_delta);
	printf("%s: detached in %7.3lfs\n", __func__, detach_delta);

cleanup:
	tracing_multi_fentry_test__destroy(skel);
}

void __test_tracing_multi_test(void)
{
	if (test__start_subtest("fentry/simple"))
		multi_fentry_test();
	if (test__start_subtest("fentry/intersected"))
		multi_fentry_intersected_test();
	if (test__start_subtest("fentry/bench"))
		multi_fentry_bench_test();
}
#else
void __test_tracing_multi_test(void)
{
	test__skip();
}
#endif /* __x86_64__ */

void test_tracing_multi_test(void)
{
	__test_tracing_multi_test();
}
