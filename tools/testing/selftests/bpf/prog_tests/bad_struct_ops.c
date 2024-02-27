// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include "bad_struct_ops.skel.h"

#define EXPECTED_MSG "libbpf: struct_ops reloc"

static libbpf_print_fn_t old_print_cb;
static bool msg_found;

static int print_cb(enum libbpf_print_level level, const char *fmt, va_list args)
{
	old_print_cb(level, fmt, args);
	if (level == LIBBPF_WARN && strncmp(fmt, EXPECTED_MSG, strlen(EXPECTED_MSG)) == 0)
		msg_found = true;

	return 0;
}

static void test_bad_struct_ops(void)
{
	struct bad_struct_ops *skel;
	int err;

	old_print_cb = libbpf_set_print(print_cb);
	skel = bad_struct_ops__open_and_load();
	err = errno;
	libbpf_set_print(old_print_cb);
	if (!ASSERT_NULL(skel, "bad_struct_ops__open_and_load"))
		return;

	ASSERT_EQ(err, EINVAL, "errno should be EINVAL");
	ASSERT_TRUE(msg_found, "expected message");

	bad_struct_ops__destroy(skel);
}

void serial_test_bad_struct_ops(void)
{
	if (test__start_subtest("test_bad_struct_ops"))
		test_bad_struct_ops();
}
