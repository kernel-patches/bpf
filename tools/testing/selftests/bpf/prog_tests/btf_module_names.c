// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <bpf/btf.h>
#include "btf_module_names.skel.h"

static void btf_module_names_load(void)
{
	struct btf_module_names *skel = NULL;
	int ret;
	const char *mod_names[] = { "bpf_testmod" };

	LIBBPF_OPTS(bpf_object_open_opts, opts,
		.btf_module_names = mod_names,
		.nr_btf_module_names = 1,
	);

	/* Verify backward compatibility. */
	skel = btf_module_names__open_opts(NULL);
	if (!ASSERT_OK_PTR(skel, "btf_module_names__open_opts default"))
		goto out;

	ret = btf_module_names__load(skel);
	ASSERT_OK(ret, "btf_module_names__load default");

	btf_module_names__destroy(skel);
	skel = NULL;

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
	const char *mod_names[] = { "module_nonexist" };

	LIBBPF_OPTS(bpf_object_open_opts, opts,
		.btf_module_names = mod_names,
		.nr_btf_module_names = 1,
	);

	skel = btf_module_names__open_opts(&opts);
	if (!ASSERT_OK_PTR(skel, "btf_module_names__open_opts"))
		goto out;

	ret = btf_module_names__load(skel);
	ASSERT_EQ(ret, -ESRCH, "btf_module_names__load");

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
	const char *mod_names[] = { NULL };

	LIBBPF_OPTS(bpf_object_open_opts, opts,
		/* Non-NULL pointer with zero entries represents an empty list. */
		.btf_module_names = mod_names,
		.nr_btf_module_names = 0,
	);

	skel = btf_module_names__open_opts(&opts);
	if (!ASSERT_OK_PTR(skel, "btf_module_names__open_opts empty"))
		goto out;

	ret = btf_module_names__load(skel);
	ASSERT_EQ(ret, -ESRCH, "btf_module_names__load empty");

out:
	btf_module_names__destroy(skel);
}

static void btf_module_names_invalid(void)
{
	struct btf_module_names *skel = NULL;
	const char *names[] = { NULL };
	const char *empty_names[] = { "" };
	const char *duplicate_names[] = {
		"bpf_testmod", "bpf_testmod",
	};
	LIBBPF_OPTS(bpf_object_open_opts, opts,
		.btf_module_names = names,
		.nr_btf_module_names = 1,
	);

	skel = btf_module_names__open_opts(&opts);
	ASSERT_EQ(libbpf_get_error(skel), -EINVAL,
		  "btf_module_names__open_opts null");
	btf_module_names__destroy(skel);

	opts.btf_module_names = empty_names;
	skel = btf_module_names__open_opts(&opts);
	ASSERT_EQ(libbpf_get_error(skel), -EINVAL,
		  "btf_module_names__open_opts empty");
	btf_module_names__destroy(skel);

	opts.btf_module_names = duplicate_names;
	opts.nr_btf_module_names = 2;
	skel = btf_module_names__open_opts(&opts);
	ASSERT_EQ(libbpf_get_error(skel), -EINVAL,
		  "btf_module_names__open_opts duplicate name");
	btf_module_names__destroy(skel);
}

void test_btf_module_names(void)
{
	struct btf *vmlinux_btf = NULL;
	struct btf *module_btf = NULL;

	if (!env.has_testmod) {
		test__skip();
		return;
	}

	vmlinux_btf = btf__load_vmlinux_btf();
	if (libbpf_get_error(vmlinux_btf)) {
		test__skip();
		return;
	}

	/* Ensure bpf_testmod BTF is available. */
	module_btf = btf__load_module_btf("bpf_testmod", vmlinux_btf);
	if (libbpf_get_error(module_btf)) {
		btf__free(vmlinux_btf);
		test__skip();
		return;
	}

	btf__free(module_btf);
	btf__free(vmlinux_btf);

	if (test__start_subtest("btf_module_names_load"))
		btf_module_names_load();

	if (test__start_subtest("btf_module_names_skip"))
		btf_module_names_skip();

	if (test__start_subtest("btf_module_names_empty"))
		btf_module_names_empty();

	if (test__start_subtest("btf_module_names_invalid"))
		btf_module_names_invalid();
}
