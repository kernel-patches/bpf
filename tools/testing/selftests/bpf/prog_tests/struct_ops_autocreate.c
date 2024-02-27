// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include "struct_ops_autocreate.skel.h"

#define EXPECTED_MSG "libbpf: struct_ops init_kern"

static libbpf_print_fn_t old_print_cb;
static bool msg_found;

static int print_cb(enum libbpf_print_level level, const char *fmt, va_list args)
{
	old_print_cb(level, fmt, args);
	if (level == LIBBPF_WARN && strncmp(fmt, EXPECTED_MSG, strlen(EXPECTED_MSG)) == 0)
		msg_found = true;

	return 0;
}

static void cant_load_full_object(void)
{
	struct struct_ops_autocreate *skel;
	int err;

	old_print_cb = libbpf_set_print(print_cb);
	skel = struct_ops_autocreate__open_and_load();
	err = errno;
	libbpf_set_print(old_print_cb);
	if (!ASSERT_NULL(skel, "struct_ops_autocreate__open_and_load"))
		return;

	ASSERT_EQ(err, ENOTSUP, "errno should be ENOTSUP");
	ASSERT_TRUE(msg_found, "expected message");

	struct_ops_autocreate__destroy(skel);
}

static void can_load_partial_object(void)
{
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);
	struct struct_ops_autocreate *skel;
	struct bpf_link *link = NULL;
	int err;

	skel = struct_ops_autocreate__open_opts(&opts);
	if (!ASSERT_OK_PTR(skel, "struct_ops_autocreate__open_opts"))
		return;

	err = bpf_map__set_autocreate(skel->maps.testmod_2, false);
	if (!ASSERT_OK(err, "bpf_map__set_autocreate"))
		goto cleanup;

	err = struct_ops_autocreate__load(skel);
	if (ASSERT_OK(err, "struct_ops_autocreate__load"))
		goto cleanup;

	link = bpf_map__attach_struct_ops(skel->maps.testmod_1);
	if (!ASSERT_OK_PTR(link, "bpf_map__attach_struct_ops"))
		goto cleanup;

	/* test_1() would be called from bpf_dummy_reg2() in bpf_testmod.c */
	ASSERT_EQ(skel->bss->test_1_result, 42, "test_1_result");

cleanup:
	bpf_link__destroy(link);
	struct_ops_autocreate__destroy(skel);
}

static void autoload_toggles(void)
{
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);
	struct bpf_map *testmod_1, *testmod_2;
	struct bpf_program *test_1, *test_2;
	struct struct_ops_autocreate *skel;

	skel = struct_ops_autocreate__open_opts(&opts);
	if (!ASSERT_OK_PTR(skel, "struct_ops_autocreate__open_opts"))
		return;

	testmod_1 = skel->maps.testmod_1;
	testmod_2 = skel->maps.testmod_2;
	test_1 = skel->progs.test_1;
	test_2 = skel->progs.test_2;

	/* testmod_1 on, testmod_2 on */
	ASSERT_TRUE(bpf_program__autoload(test_1), "autoload(test_1) #1");
	ASSERT_TRUE(bpf_program__autoload(test_2), "autoload(test_2) #1");

	/* testmod_1 off, testmod_2 on */
	bpf_map__set_autocreate(testmod_1, false);
	ASSERT_TRUE(bpf_program__autoload(test_1), "autoload(test_1) #2");
	ASSERT_TRUE(bpf_program__autoload(test_2), "autoload(test_2) #2");

	/* testmod_1 off, testmod_2 off,
	 * setting same state several times should not confuse internal state.
	 */
	bpf_map__set_autocreate(testmod_2, false);
	bpf_map__set_autocreate(testmod_2, false);
	ASSERT_FALSE(bpf_program__autoload(test_1), "autoload(test_1) #3");
	ASSERT_FALSE(bpf_program__autoload(test_2), "autoload(test_2) #3");

	/* testmod_1 on, testmod_2 off */
	bpf_map__set_autocreate(testmod_1, true);
	bpf_map__set_autocreate(testmod_1, true);
	ASSERT_TRUE(bpf_program__autoload(test_1), "autoload(test_1) #4");
	ASSERT_FALSE(bpf_program__autoload(test_2), "autoload(test_2) #4");

	/* testmod_1 on, testmod_2 on */
	bpf_map__set_autocreate(testmod_2, true);
	ASSERT_TRUE(bpf_program__autoload(test_1), "autoload(test_1) #5");
	ASSERT_TRUE(bpf_program__autoload(test_2), "autoload(test_2) #5");

	/* testmod_1 on, testmod_2 off */
	bpf_map__set_autocreate(testmod_2, false);
	ASSERT_TRUE(bpf_program__autoload(test_1), "autoload(test_1) #6");
	ASSERT_FALSE(bpf_program__autoload(test_2), "autoload(test_2) #6");

	/* setting autoload manually overrides automatic toggling */
	bpf_program__set_autoload(test_2, false);
	/* testmod_1 on, testmod_2 off */
	bpf_map__set_autocreate(testmod_2, true);
	ASSERT_TRUE(bpf_program__autoload(test_1), "autoload(test_1) #7");
	ASSERT_FALSE(bpf_program__autoload(test_2), "autoload(test_2) #7");

	struct_ops_autocreate__destroy(skel);
}

void serial_test_struct_ops_autocreate(void)
{
	if (test__start_subtest("autoload_toggles"))
		autoload_toggles();
	if (test__start_subtest("cant_load_full_object"))
		cant_load_full_object();
	if (test__start_subtest("can_load_partial_object"))
		can_load_partial_object();
}
