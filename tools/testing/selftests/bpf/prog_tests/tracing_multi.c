// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include <bpf/btf.h>
#include <search.h>
#include "bpf/libbpf_internal.h"
#include "tracing_multi.skel.h"
#include "tracing_multi_intersect.skel.h"
#include "tracing_multi_session.skel.h"
#include "tracing_multi_bench.skel.h"
#include "trace_helpers.h"

static __u64 bpf_fentry_test_cookies[] = {
	8,  /* bpf_fentry_test1 */
	9,  /* bpf_fentry_test2 */
	7,  /* bpf_fentry_test3 */
	5,  /* bpf_fentry_test4 */
	4,  /* bpf_fentry_test5 */
	2,  /* bpf_fentry_test6 */
	3,  /* bpf_fentry_test7 */
	1,  /* bpf_fentry_test8 */
	10, /* bpf_fentry_test9 */
	6,  /* bpf_fentry_test10 */
};

static const char * const bpf_fentry_test[] = {
	"bpf_fentry_test1",
	"bpf_fentry_test2",
	"bpf_fentry_test3",
	"bpf_fentry_test4",
	"bpf_fentry_test5",
	"bpf_fentry_test6",
	"bpf_fentry_test7",
	"bpf_fentry_test8",
	"bpf_fentry_test9",
	"bpf_fentry_test10",
};

#define FUNCS_CNT (ARRAY_SIZE(bpf_fentry_test))

static int get_random_funcs(const char **funcs)
{
	int i, cnt = 0;

	for (i = 0; i < FUNCS_CNT; i++) {
		if (rand() % 2)
			funcs[cnt++] = bpf_fentry_test[i];
	}
	/* we always need at least one.. */
	if (!cnt)
		funcs[cnt++] = bpf_fentry_test[rand() % FUNCS_CNT];
	return cnt;
}

static int compare(const void *ppa, const void *ppb)
{
	const char *pa = *(const char **) ppa;
	const char *pb = *(const char **) ppb;

	return strcmp(pa, pb);
}

static __u32 *get_ids(const char * const funcs[], int funcs_cnt)
{
	__u32 nr, type_id, cnt = 0;
	void *root = NULL;
	__u32 *ids = NULL;
	struct btf *btf;
	int i, err = 0;

	btf = btf__load_vmlinux_btf();
	if (!ASSERT_OK_PTR(btf, "btf__load_vmlinux_btf"))
		return NULL;

	ids = calloc(funcs_cnt, sizeof(ids[0]));
	if (!ids)
		goto out;

	/*
	 * We sort function names by name and search them
	 * below for each function.
	 */
	for (i = 0; i < funcs_cnt; i++)
		tsearch(&funcs[i], &root, compare);

	nr = btf__type_cnt(btf);
	for (type_id = 1; type_id < nr && cnt < funcs_cnt; type_id++) {
		const struct btf_type *type;
		const char *str, ***val;
		unsigned int idx;

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

		val = tfind(&str, &root, compare);
		if (!val)
			continue;

		/*
		 * We keep pointer for each function name so we can get the original
		 * array index and have the resulting ids array matching the original
		 * function array.
		 *
		 * Doing it this way allow us to easily test the cookies support,
		 * because each cookie is attach to particular function/id.
		 */
		idx = *val - funcs;
		ids[idx] = type_id;
		cnt++;
	}

	if (err) {
		free(ids);
		ids = NULL;
	}

out:
	btf__free(btf);
	return ids;
}

static void tracing_multi_test_run(struct tracing_multi *skel)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	int err, prog_fd;

	prog_fd = bpf_program__fd(skel->progs.test_fentry);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_run");

	ASSERT_EQ(skel->bss->test_result_fentry, FUNCS_CNT, "test_result_fentry");
	ASSERT_EQ(skel->bss->test_result_fexit, FUNCS_CNT, "test_result_fexit");
}

static void test_skel_api(void)
{
	struct tracing_multi *skel = NULL;
	int err;

	skel = tracing_multi__open_and_load();
	if (!ASSERT_OK_PTR(skel, "tracing_multi__open_and_load"))
		return;

	skel->bss->pid = getpid();

	err = tracing_multi__attach(skel);
	if (!ASSERT_OK(err, "tracing_multi__attach"))
		goto cleanup;

	tracing_multi_test_run(skel);

cleanup:
	tracing_multi__destroy(skel);
}

static void test_link_api_pattern(void)
{
	struct tracing_multi *skel = NULL;

	skel = tracing_multi__open_and_load();
	if (!ASSERT_OK_PTR(skel, "tracing_multi__open_and_load"))
		return;

	skel->bss->pid = getpid();

	skel->links.test_fentry = bpf_program__attach_tracing_multi(skel->progs.test_fentry,
					"bpf_fentry_test*", NULL);
	if (!ASSERT_OK_PTR(skel->links.test_fentry, "bpf_program__attach_tracing_multi"))
		goto cleanup;

	skel->links.test_fexit = bpf_program__attach_tracing_multi(skel->progs.test_fexit,
					"bpf_fentry_test*", NULL);
	if (!ASSERT_OK_PTR(skel->links.test_fexit, "bpf_program__attach_tracing_multi"))
		goto cleanup;

	tracing_multi_test_run(skel);

cleanup:
	tracing_multi__destroy(skel);
}

static void test_link_api_ids(bool test_cookies)
{
	LIBBPF_OPTS(bpf_tracing_multi_opts, opts);
	struct tracing_multi *skel = NULL;
	size_t cnt = FUNCS_CNT;
	__u32 *ids;

	skel = tracing_multi__open_and_load();
	if (!ASSERT_OK_PTR(skel, "tracing_multi__open_and_load"))
		return;

	skel->bss->pid = getpid();
	skel->bss->test_cookies = test_cookies;

	ids = get_ids(bpf_fentry_test, cnt);
	if (!ASSERT_OK_PTR(ids, "get_ids"))
		goto cleanup;

	opts.ids = ids;
	opts.cnt = cnt;

	if (test_cookies)
		opts.cookies = bpf_fentry_test_cookies;

	skel->links.test_fentry = bpf_program__attach_tracing_multi(skel->progs.test_fentry,
						NULL, &opts);
	if (!ASSERT_OK_PTR(skel->links.test_fentry, "bpf_program__attach_tracing_multi"))
		goto cleanup;

	skel->links.test_fexit = bpf_program__attach_tracing_multi(skel->progs.test_fexit,
						NULL, &opts);
	if (!ASSERT_OK_PTR(skel->links.test_fexit, "bpf_program__attach_tracing_multi"))
		goto cleanup;

	tracing_multi_test_run(skel);

cleanup:
	tracing_multi__destroy(skel);
}

static bool is_set(__u32 mask, __u32 bit)
{
	return (1 << bit) & mask;
}

static void __test_intersect(__u32 mask, const struct bpf_program *progs[4], __u64 *test_results[4])
{
	LIBBPF_OPTS(bpf_tracing_multi_opts, opts);
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	struct bpf_link *links[4] = { NULL };
	const char *funcs[FUNCS_CNT];
	__u64 expected[4];
	__u32 *ids, i;
	int err, cnt;

	/*
	 * We have 4 programs in progs and the mask bits pick which
	 * of them gets attached to randomly chosen functions.
	 */
	for (i = 0; i < 4; i++) {
		if (!is_set(mask, i))
			continue;

		cnt = get_random_funcs(funcs);
		ids = get_ids(funcs, cnt);
		if (!ASSERT_OK_PTR(ids, "get_ids"))
			goto cleanup;

		opts.ids = ids;
		opts.cnt = cnt;
		links[i] = bpf_program__attach_tracing_multi(progs[i], NULL, &opts);
		free(ids);

		if (!ASSERT_OK_PTR(links[i], "bpf_program__attach_tracing_multi"))
			goto cleanup;

		expected[i] = *test_results[i] + cnt;
	}

	err = bpf_prog_test_run_opts(bpf_program__fd(progs[0]), &topts);
	ASSERT_OK(err, "test_run");

	for (i = 0; i < 4; i++) {
		if (!is_set(mask, i))
			continue;
		ASSERT_EQ(*test_results[i], expected[i], "test_results");
	}

cleanup:
	for (i = 0; i < 4; i++)
		bpf_link__destroy(links[i]);
}

static void test_intersect(void)
{
	const struct bpf_program *progs[4];
	struct tracing_multi_intersect *skel;
	__u64 *test_results[4];
	__u32 i;

	skel = tracing_multi_intersect__open_and_load();
	if (!ASSERT_OK_PTR(skel, "tracing_multi_intersect__open_and_load"))
		return;

	skel->bss->pid = getpid();

	progs[0] = skel->progs.fentry_1;
	progs[1] = skel->progs.fexit_1;
	progs[2] = skel->progs.fentry_2;
	progs[3] = skel->progs.fexit_2;

	test_results[0] = &skel->bss->test_result_fentry_1;
	test_results[1] = &skel->bss->test_result_fexit_1;
	test_results[2] = &skel->bss->test_result_fentry_2;
	test_results[3] = &skel->bss->test_result_fexit_2;

	for (i = 1; i < 16; i++)
		__test_intersect(i, progs, test_results);

	tracing_multi_intersect__destroy(skel);
}

static void test_session(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	struct tracing_multi_session *skel;
	int err, prog_fd;

	skel = tracing_multi_session__open_and_load();
	if (!ASSERT_OK_PTR(skel, "tracing_multi_session__open_and_load"))
		return;

	skel->bss->pid = getpid();

	err = tracing_multi_session__attach(skel);
	if (!ASSERT_OK(err, "tracing_multi_session__attach"))
		goto cleanup;

	prog_fd = bpf_program__fd(skel->progs.test_session);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_run");

	ASSERT_EQ(skel->bss->test_result_fentry, 10, "test_result_fentry");
	/* extra count for test_result_fexit cookie */
	ASSERT_EQ(skel->bss->test_result_fexit, 20, "test_result_fexit");

cleanup:
	tracing_multi_session__destroy(skel);
}

static void test_attach_api_fails(void)
{
	LIBBPF_OPTS(bpf_tracing_multi_opts, opts);
	struct tracing_multi *skel = NULL;
	__u64 cookies[2];
	__u32 ids[2];

	skel = tracing_multi__open_and_load();
	if (!ASSERT_OK_PTR(skel, "tracing_multi__open_and_load"))
		return;

	/* fail#1 pattern and opts NULL */
	skel->links.test_fentry = bpf_program__attach_tracing_multi(skel->progs.test_fentry,
						NULL, NULL);
	if (!ASSERT_ERR_PTR(skel->links.test_fentry, "bpf_program__attach_tracing_multi"))
		goto cleanup;

	/* fail#2 pattern and ids */
	opts.ids = ids;
	opts.cnt = 2;

	skel->links.test_fentry = bpf_program__attach_tracing_multi(skel->progs.test_fentry,
						"bpf_fentry_test*", &opts);
	if (!ASSERT_ERR_PTR(skel->links.test_fentry, "bpf_program__attach_tracing_multi"))
		goto cleanup;

	/* fail#3 pattern and cookies */
	opts.ids = NULL;
	opts.cnt = 2;
	opts.cookies = cookies;

	skel->links.test_fentry = bpf_program__attach_tracing_multi(skel->progs.test_fentry,
						"bpf_fentry_test*", &opts);
	if (!ASSERT_ERR_PTR(skel->links.test_fentry, "bpf_program__attach_tracing_multi"))
		goto cleanup;

	/* fail#4 bogus pattern */
	skel->links.test_fentry = bpf_program__attach_tracing_multi(skel->progs.test_fentry,
						"bpf_not_really_a_function*", NULL);
	if (!ASSERT_ERR_PTR(skel->links.test_fentry, "bpf_program__attach_tracing_multi"))
		goto cleanup;

	/* fail#5 abnormal cnt */
	opts.ids = ids;
	opts.cnt = INT_MAX;

	skel->links.test_fentry = bpf_program__attach_tracing_multi(skel->progs.test_fentry,
						NULL, &opts);
	ASSERT_ERR_PTR(skel->links.test_fentry, "bpf_program__attach_tracing_multi");

cleanup:
	tracing_multi__destroy(skel);
}

/*
 * Skip several kernel symbols that might not be safe or could cause delays.
 */
static bool skip_symbol(char *name)
{
	if (!strcmp(name, "arch_cpu_idle"))
		return true;
	if (!strcmp(name, "default_idle"))
		return true;
	if (!strncmp(name, "rcu_", 4))
		return true;
	if (!strcmp(name, "bpf_dispatcher_xdp_func"))
		return true;
	if (strstr(name, "rcu"))
		return true;
	if (strstr(name, "trace"))
		return true;
	if (strstr(name, "irq"))
		return true;
	if (strstr(name, "bpf_lsm_"))
		return true;
	if (!strcmp(name, "migrate_enable"))
		return true;
	if (!strcmp(name, "migrate_disable"))
		return true;
	if (!strcmp(name, "preempt_count_sub"))
		return true;
	if (!strcmp(name, "preempt_count_add"))
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

	if (btf_is_struct(t) || btf_is_union(t))
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

void serial_test_tracing_multi_bench_attach(void)
{
	LIBBPF_OPTS(bpf_tracing_multi_opts, opts);
	struct tracing_multi_bench *skel = NULL;
	size_t i, syms_cnt, cap = 0, cnt = 0;
	long attach_start_ns, attach_end_ns;
	long detach_start_ns, detach_end_ns;
	double attach_delta, detach_delta;
	struct bpf_link *link = NULL;
	void *root = NULL;
	__u32 *ids = NULL;
	__u32 nr, type_id;
	struct btf *btf;
	char **syms;
	int err;

#ifndef __x86_64__
	test__skip();
	return;
#endif

	btf = btf__load_vmlinux_btf();
	if (!ASSERT_OK_PTR(btf, "btf__load_vmlinux_btf"))
		return;

	skel = tracing_multi_bench__open_and_load();
	if (!ASSERT_OK_PTR(skel, "tracing_multi_bench__open_and_load"))
		goto cleanup;

	if (!ASSERT_OK(bpf_get_ksyms(&syms, &syms_cnt, true), "get_syms"))
		goto cleanup;

	for (i = 0; i < syms_cnt; i++) {
		if (skip_symbol(syms[i]))
			continue;
		tsearch(&syms[i], &root, compare);
	}

	nr = btf__type_cnt(btf);
	for (type_id = 1; type_id < nr; type_id++) {
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

		if (!tfind(&str, &root, compare))
			continue;

		if (!is_allowed_func(btf, type))
			continue;

		err = libbpf_ensure_mem((void **) &ids, &cap, sizeof(*ids), cnt + 1);
		if (err)
			break;

		ids[cnt++] = type_id;
	}

	opts.ids = ids;
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
	tracing_multi_bench__destroy(skel);
}

void test_tracing_multi_test(void)
{
#ifndef __x86_64__
	test__skip();
	return;
#endif

	if (test__start_subtest("skel_api"))
		test_skel_api();
	if (test__start_subtest("link_api_pattern"))
		test_link_api_pattern();
	if (test__start_subtest("link_api_ids"))
		test_link_api_ids(false);
	if (test__start_subtest("intersect"))
		test_intersect();
	if (test__start_subtest("cookies"))
		test_link_api_ids(true);
	if (test__start_subtest("session"))
		test_session();
	if (test__start_subtest("attach_api_fails"))
		test_attach_api_fails();
}
