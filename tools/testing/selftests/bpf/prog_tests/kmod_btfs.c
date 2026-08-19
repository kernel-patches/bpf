// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "kmod_btfs.skel.h"

static bool btf_skipped;
static bool dup_ignored;

static const char btf_skip_fmt[] =
	"libbpf: skipping module BTF '%s', not in kmod_btf_names\n";
static const char dup_ignore_fmt[] =
	"libbpf: duplicate kmod BTF name '%s' ignored\n";

static int libbpf_print_cb(enum libbpf_print_level level, const char *fmt,
			   va_list args)
{
	if (!strcmp(fmt, btf_skip_fmt)) {
		if (!strcmp(va_arg(args, char *), "bpf_test_no_cfi"))
			btf_skipped = true;
	} else if (!strcmp(fmt, dup_ignore_fmt)) {
		if (!strcmp(va_arg(args, char *), "bpf_testmod"))
			dup_ignored = true;
	}

	return 0;
}

static void kmod_btfs_pass(void)
{
	struct kmod_btfs *skel = NULL;
	int ret;
	static const char *kmods[] = { "bpf_testmod" };

	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts,
		.kmod_btf_names = kmods,
		.kmod_btf_names_cnt = 1,
	);

	skel = kmod_btfs__open_opts(&opts);
	if (!ASSERT_OK_PTR(skel, "kmod_btfs__open_opts"))
		goto out;

	ret = kmod_btfs__load(skel);
	ASSERT_OK(ret, "kmod_btfs__load");
out:
	kmod_btfs__destroy(skel);
}

static void kmod_btfs_nonexist(void)
{
	struct kmod_btfs *skel = NULL;
	int ret;
	static const char *nonexist_kmods[] = { "module_nonexist" };

	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts,
		.kmod_btf_names = nonexist_kmods,
		.kmod_btf_names_cnt = 1,
	);

	/*
	 * Only "module_nonexist" is requested; since it does not exist in
	 * the kernel, no module BTF gets loaded. The BPF program then
	 * fails to load because the real needed module's BTF is unavailable.
	 */
	skel = kmod_btfs__open_opts(&opts);
	if (!ASSERT_OK_PTR(skel, "kmod_btfs__open_opts"))
		goto out;

	ret = kmod_btfs__load(skel);
	ASSERT_ERR(ret, "kmod_btfs__load");

out:
	kmod_btfs__destroy(skel);
}

static void kmod_btfs_dup(void)
{
	struct kmod_btfs *skel = NULL;
	libbpf_print_fn_t old_print_cb;
	int ret;
	static const char *dup_kmods[] = { "bpf_testmod", "bpf_testmod" };

	/* duplicate entry on purpose: libbpf should dedupe it with a warning */
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts,
		.kmod_btf_names = dup_kmods,
		.kmod_btf_names_cnt = 2,
	);

	dup_ignored = false;
	old_print_cb = libbpf_set_print(libbpf_print_cb);

	skel = kmod_btfs__open_opts(&opts);
	if (!ASSERT_OK_PTR(skel, "kmod_btfs__open_opts"))
		goto out;

	ASSERT_TRUE(dup_ignored, "dup_ignored");

	ret = kmod_btfs__load(skel);
	ASSERT_OK(ret, "kmod_btfs__load");

	kmod_btfs__destroy(skel);
out:
	libbpf_set_print(old_print_cb);
}

static void kmod_btfs_skip(void)
{
	struct kmod_btfs *skel = NULL;
	libbpf_print_fn_t old_print_cb;
	bool testmod_unloaded = false;
	int ret;
	static const char *kmods[] = { "bpf_testmod" };

	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts,
		.kmod_btf_names = kmods,
		.kmod_btf_names_cnt = 1,
	);

	btf_skipped = false;
	old_print_cb = libbpf_set_print(libbpf_print_cb);

	/*
	 * Reload bpf_testmod after bpf_test_no_cfi to ensure the unneeded
	 * module's BTF is enumerated first and skipped.
	 */
	if (!ASSERT_OK(unload_bpf_testmod(false), "unload bpf_testmod"))
		goto cleanup_print;
	testmod_unloaded = true;

	if (!ASSERT_OK(load_module("bpf_test_no_cfi.ko", false),
		       "load unneeded bpf_test_no_cfi module"))
		goto cleanup_print;
	if (!ASSERT_OK(load_bpf_testmod(false), "restore bpf_testmod"))
		goto cleanup_module;
	testmod_unloaded = false;

	skel = kmod_btfs__open_opts(&opts);
	if (!ASSERT_OK_PTR(skel, "kmod_btfs__open_opts"))
		goto cleanup_module;

	ret = kmod_btfs__load(skel);
	if (!ASSERT_OK(ret, "kmod_btfs__load"))
		goto cleanup_skel;

	ASSERT_TRUE(btf_skipped, "btf_skipped");

cleanup_skel:
	kmod_btfs__destroy(skel);
cleanup_module:
	ASSERT_OK(unload_module("bpf_test_no_cfi", false),
		  "unload unneeded bpf_test_no_cfi module");
cleanup_print:
	if (testmod_unloaded)
		ASSERT_OK(load_bpf_testmod(false),
			  "restore bpf_testmod on error path");
	libbpf_set_print(old_print_cb);
}

static void kmod_btfs_no_cnt(void)
{
	struct kmod_btfs *skel = NULL;
	static const char *kmods[] = { "bpf_testmod" };

	/*
	 * kmod_btf_names set but kmod_btf_names_cnt not set:
	 * open must fail with -EINVAL.
	 */
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts,
		.kmod_btf_names = kmods,
	);

	skel = kmod_btfs__open_opts(&opts);
	ASSERT_NULL(skel, "kmod_btfs__open_opts without kmod_btf_names_cnt");
}

void serial_test_kmod_btfs(void)
{
	if (!env.has_testmod) {
		test__skip();
		return;
	}

	if (test__start_subtest("kmod_btfs_pass"))
		kmod_btfs_pass();

	if (test__start_subtest("kmod_btfs_nonexist"))
		kmod_btfs_nonexist();

	if (test__start_subtest("kmod_btfs_dup"))
		kmod_btfs_dup();

	if (test__start_subtest("kmod_btfs_skip"))
		kmod_btfs_skip();

	if (test__start_subtest("kmod_btfs_no_cnt"))
		kmod_btfs_no_cnt();
}
