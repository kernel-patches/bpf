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

	err = bpf_program__set_autoload(skel->progs.test_2, false);
	if (!ASSERT_OK(err, "bpf_program__set_autoload"))
		goto cleanup;

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

void serial_test_struct_ops_autocreate(void)
{
	if (test__start_subtest("cant_load_full_object"))
		cant_load_full_object();
	if (test__start_subtest("can_load_partial_object"))
		can_load_partial_object();
}
