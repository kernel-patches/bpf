// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2024. Huawei Technologies Co., Ltd */
#include "test_progs.h"
#include "read_vsyscall.skel.h"

#if defined(__x86_64__)
/* For VSYSCALL_ADDR */
#include <asm/vsyscall.h>
#else
/* To prevent build failure on non-x86 arch */
#define VSYSCALL_ADDR 0UL
#endif

struct read_ret_desc {
	const char *name;
	int ret;
};

struct read_ret_desc all_probe_read[] = {
	{ .name = "probe_read_kernel", .ret = -ERANGE },
	{ .name = "probe_read_kernel_str", .ret = -ERANGE },
	{ .name = "probe_read", .ret = -ERANGE },
	{ .name = "probe_read_str", .ret = -ERANGE },
	{ .name = "probe_read_user", .ret = -EFAULT },
	{ .name = "probe_read_user_str", .ret = -EFAULT },
};

struct read_ret_desc all_copy_from_user[] = {
	{ .name = "copy_from_user", .ret = -EFAULT },
	{ .name = "copy_from_user_task", .ret = -EFAULT },
	{ .name = "copy_from_user_str", .ret = -EFAULT },
	{ .name = "copy_from_user_task_str", .ret = -EFAULT },
};

static void test_read_vsyscall_subtest(const char *prog_name,
				       const struct read_ret_desc *descs,
				       unsigned int cnt)
{
	struct read_vsyscall *skel;
	struct bpf_program *prog;
	unsigned int i;
	int err;

#if !defined(__x86_64__)
	test__skip();
	return;
#endif
	skel = read_vsyscall__open();
	if (!ASSERT_OK_PTR(skel, "read_vsyscall open"))
		return;

	prog = bpf_object__find_program_by_name(skel->obj, prog_name);
	if (!ASSERT_OK_PTR(prog, "read_vsyscall find program"))
		goto out;
	bpf_program__set_autoload(prog, true);

	err = read_vsyscall__load(skel);
	if (!ASSERT_EQ(err, 0, "read_vsyscall load"))
		goto out;

	skel->bss->target_pid = getpid();
	err = read_vsyscall__attach(skel);
	if (!ASSERT_EQ(err, 0, "read_vsyscall attach"))
		goto out;

	/* userspace may don't have vsyscall page due to LEGACY_VSYSCALL_NONE,
	 * but it doesn't affect the returned error codes.
	 */
	skel->bss->user_ptr = (void *)VSYSCALL_ADDR;
	usleep(1);

	for (i = 0; i < cnt; i++)
		ASSERT_EQ(skel->bss->read_ret[i], descs[i].ret, descs[i].name);
out:
	read_vsyscall__destroy(skel);
}

void test_read_vsyscall(void)
{
	if (test__start_subtest("probe_read")) {
		test_read_vsyscall_subtest("probe_read", all_probe_read,
					   ARRAY_SIZE(all_probe_read));
	}
	if (test__start_subtest("copy_from_user")) {
		test_read_vsyscall_subtest("copy_from_user", all_copy_from_user,
					   ARRAY_SIZE(all_copy_from_user));
	}
}
