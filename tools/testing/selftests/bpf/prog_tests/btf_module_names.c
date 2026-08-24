// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "btf_module_names.skel.h"

static void btf_module_names_load(void)
{
	struct btf_module_names *skel = NULL;
	int ret;
	static const char *mod_names[] = { "bpf_testmod" };

	LIBBPF_OPTS(bpf_object_open_opts, opts,
		.btf_module_names = mod_names,
		.nr_btf_module_names = 1,
	);

	skel = btf_module_names__open_opts(&opts);
	if (!ASSERT_OK_PTR(skel, "btf_module_names__open_opts"))
		goto out;

	ret = btf_module_names__load(skel);
	ASSERT_OK(ret, "btf_module_names__load");
out:
	btf_module_names__destroy(skel);
}

/*
 * Verify that an unrequested module BTF is skipped. The BPF program
 * requires the BTF of bpf_testmod, but bpf_testmod is not specified in
 * btf_module_names, so its BTF is skipped and the BPF program fails to load.
 */
static void btf_module_names_skip(void)
{
	struct btf_module_names *skel = NULL;
	int ret;
	static const char *mod_names[] = { "module_nonexist" };

	LIBBPF_OPTS(bpf_object_open_opts, opts,
		.btf_module_names = mod_names,
		.nr_btf_module_names = 1,
	);

	skel = btf_module_names__open_opts(&opts);
	if (!ASSERT_OK_PTR(skel, "btf_module_names__open_opts"))
		goto out;

	ret = btf_module_names__load(skel);
	ASSERT_ERR(ret, "btf_module_names__load");

out:
	btf_module_names__destroy(skel);
}

/*
 * Verify that an empty filter skips loading all module BTFs. The BPF
 * program requires bpf_testmod BTF, so it fails to load.
 */
static void btf_module_names_empty(void)
{
	struct btf_module_names *skel = NULL;
	int ret;
	static const char *mod_names[] = { "foo" };

	LIBBPF_OPTS(bpf_object_open_opts, opts,
		.btf_module_names = mod_names,
	);

	skel = btf_module_names__open_opts(&opts);
	if (!ASSERT_OK_PTR(skel, "btf_module_names__open_opts empty"))
		goto out;

	ret = btf_module_names__load(skel);
	ASSERT_ERR(ret, "btf_module_names__load empty");

out:
	btf_module_names__destroy(skel);
}

void test_btf_module_names(void)
{
	if (!env.has_testmod) {
		test__skip();
		return;
	}

	if (test__start_subtest("btf_module_names_load"))
		btf_module_names_load();

	if (test__start_subtest("btf_module_names_skip"))
		btf_module_names_skip();

	if (test__start_subtest("btf_module_names_empty"))
		btf_module_names_empty();
}
