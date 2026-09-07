// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <bpf/btf.h>
#include "btf_module_allowlist.skel.h"

static void test_load_with_list(const char **list, int count, int expected_ret)
{
	struct btf_module_allowlist *skel;
	int ret;
	LIBBPF_OPTS(bpf_object_open_opts, opts,
		.btf_module_allowlist = list,
		.btf_module_allowlist_cnt = count,
	);

	skel = btf_module_allowlist__open_opts(&opts);
	if (!ASSERT_OK_PTR(skel, "btf_module_allowlist__open_opts"))
		return;

	ret = btf_module_allowlist__load(skel);
	ASSERT_EQ(ret, expected_ret, "btf_module_allowlist__load");

	btf_module_allowlist__destroy(skel);
}

static void btf_module_allowlist_default(void)
{
	struct btf_module_allowlist *skel;
	int ret;
	LIBBPF_OPTS(bpf_object_open_opts, opts);

	skel = btf_module_allowlist__open();
	if (!ASSERT_OK_PTR(skel, "btf_module_allowlist__open"))
		return;

	ret = btf_module_allowlist__load(skel);
	ASSERT_OK(ret, "btf_module_allowlist__load");

	btf_module_allowlist__destroy(skel);
	skel = NULL;

	skel = btf_module_allowlist__open_opts(&opts);
	if (!ASSERT_OK_PTR(skel, "btf_module_allowlist__open_opts"))
		return;

	ret = btf_module_allowlist__load(skel);
	ASSERT_OK(ret, "btf_module_allowlist__load opts");

	btf_module_allowlist__destroy(skel);
}

static void btf_module_allowlist_allow(void)
{
	const char *mod_list[] = { "bpf_testmod" };

	test_load_with_list(mod_list, 1, 0);
}

/*
 * bpf_testmod is not in the allowlist, so loading should fail.
 */
static void btf_module_allowlist_skip(void)
{
	const char *mod_list[] = { "module_nonexist" };

	test_load_with_list(mod_list, 1, -ESRCH);
}

/*
 * An empty allowlist skips all module BTFs, so loading should fail.
 */
static void btf_module_allowlist_empty(void)
{
	const char *mod_list[] = { NULL };

	test_load_with_list(mod_list, 0, -ESRCH);
}

static void test_invalid_input(const char **list, int count,
			       const char *test_name)
{
	struct btf_module_allowlist *skel;
	char assert_name[64];
	LIBBPF_OPTS(bpf_object_open_opts, opts,
		.btf_module_allowlist = list,
		.btf_module_allowlist_cnt = count,
	);

	snprintf(assert_name, sizeof(assert_name), "%s: open_opts", test_name);
	skel = btf_module_allowlist__open_opts(&opts);
	if (!ASSERT_NULL(skel, assert_name)) {
		btf_module_allowlist__destroy(skel);
		return;
	}
	snprintf(assert_name, sizeof(assert_name), "%s: open_opts err", test_name);
	ASSERT_EQ(errno, EINVAL, assert_name);
}

static void btf_module_allowlist_invalid(void)
{
	const char *names[] = { NULL };
	const char *empty_names[] = { "" };
	const char *duplicate_names[] = { "bpf_testmod", "bpf_testmod" };

	test_invalid_input(NULL, 1, "null_list");
	test_invalid_input(NULL, -1, "negative_count");
	test_invalid_input(names, 1, "null_name");
	test_invalid_input(empty_names, 1, "empty_name");
	test_invalid_input(duplicate_names, 2, "duplicate_name");
}

void test_btf_module_allowlist(void)
{
	struct btf *vmlinux_btf = NULL;
	struct btf *module_btf = NULL;

	if (!env.has_testmod) {
		printf("%s:SKIP: bpf_testmod is not available\n", __func__);
		test__skip();
		return;
	}

	vmlinux_btf = btf__load_vmlinux_btf();
	if (libbpf_get_error(vmlinux_btf)) {
		printf("%s:SKIP: vmlinux_btf is not available\n", __func__);
		test__skip();
		return;
	}

	/* Ensure bpf_testmod BTF is available. */
	module_btf = btf__load_module_btf("bpf_testmod", vmlinux_btf);
	if (libbpf_get_error(module_btf)) {
		printf("%s:SKIP: bpf_testmod's BTF is not available\n", __func__);
		btf__free(vmlinux_btf);
		test__skip();
		return;
	}

	btf__free(module_btf);
	btf__free(vmlinux_btf);

	if (test__start_subtest("default"))
		btf_module_allowlist_default();

	if (test__start_subtest("allowlist"))
		btf_module_allowlist_allow();

	if (test__start_subtest("skip_unlisted"))
		btf_module_allowlist_skip();

	if (test__start_subtest("emptylist"))
		btf_module_allowlist_empty();

	if (test__start_subtest("invalid_input"))
		btf_module_allowlist_invalid();
}
