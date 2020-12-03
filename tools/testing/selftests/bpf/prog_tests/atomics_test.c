// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>


#include "atomics_test.skel.h"

static struct atomics_test *setup(void)
{
	struct atomics_test *atomics_skel;
	__u32 duration = 0, err;

	atomics_skel = atomics_test__open_and_load();
	if (CHECK(!atomics_skel, "atomics_skel_load", "atomics skeleton failed\n"))
		return NULL;

	if (atomics_skel->data->skip_tests) {
		printf("%s:SKIP:no ENABLE_ATOMICS_TEST (missing Clang BPF atomics support)",
		       __func__);
		test__skip();
		goto err;
	}

	err = atomics_test__attach(atomics_skel);
	if (CHECK(err, "atomics_attach", "atomics attach failed: %d\n", err))
		goto err;

	return atomics_skel;

err:
	atomics_test__destroy(atomics_skel);
	return NULL;
}

static void test_add(void)
{
	struct atomics_test *atomics_skel;
	int err, prog_fd;
	__u32 duration = 0, retval;

	atomics_skel = setup();
	if (!atomics_skel)
		return;

	prog_fd = bpf_program__fd(atomics_skel->progs.add);
	err = bpf_prog_test_run(prog_fd, 1, NULL, 0,
				NULL, NULL, &retval, &duration);
	if (CHECK(err || retval, "test_run add",
		  "err %d errno %d retval %d duration %d\n",
		  err, errno, retval, duration))
		goto cleanup;

	ASSERT_EQ(atomics_skel->data->add64_value, 3, "add64_value");
	ASSERT_EQ(atomics_skel->bss->add64_result, 1, "add64_result");

	ASSERT_EQ(atomics_skel->data->add32_value, 3, "add32_value");
	ASSERT_EQ(atomics_skel->bss->add32_result, 1, "add32_result");

	ASSERT_EQ(atomics_skel->bss->add_stack_value_copy, 3, "add_stack_value");
	ASSERT_EQ(atomics_skel->bss->add_stack_result, 1, "add_stack_result");

	ASSERT_EQ(atomics_skel->data->add_noreturn_value, 3, "add_noreturn_value");

cleanup:
	atomics_test__destroy(atomics_skel);
}

static void test_sub(void)
{
	struct atomics_test *atomics_skel;
	int err, prog_fd;
	__u32 duration = 0, retval;

	atomics_skel = setup();
	if (!atomics_skel)
		return;

	prog_fd = bpf_program__fd(atomics_skel->progs.sub);
	err = bpf_prog_test_run(prog_fd, 1, NULL, 0,
				NULL, NULL, &retval, &duration);
	if (CHECK(err || retval, "test_run sub",
		  "err %d errno %d retval %d duration %d\n",
		  err, errno, retval, duration))
		goto cleanup;

	ASSERT_EQ(atomics_skel->data->sub64_value, -1, "sub64_value");
	ASSERT_EQ(atomics_skel->bss->sub64_result, 1, "sub64_result");

	ASSERT_EQ(atomics_skel->data->sub32_value, -1, "sub32_value");
	ASSERT_EQ(atomics_skel->bss->sub32_result, 1, "sub32_result");

	ASSERT_EQ(atomics_skel->bss->sub_stack_value_copy, -1, "sub_stack_value");
	ASSERT_EQ(atomics_skel->bss->sub_stack_result, 1, "sub_stack_result");

	ASSERT_EQ(atomics_skel->data->sub_noreturn_value, -1, "sub_noreturn_value");

cleanup:
	atomics_test__destroy(atomics_skel);
}

static void test_and(void)
{
	struct atomics_test *atomics_skel;
	int err, prog_fd;
	__u32 duration = 0, retval;

	atomics_skel = setup();
	if (!atomics_skel)
		return;

	prog_fd = bpf_program__fd(atomics_skel->progs.and);
	err = bpf_prog_test_run(prog_fd, 1, NULL, 0,
				NULL, NULL, &retval, &duration);
	if (CHECK(err || retval, "test_run and",
		  "err %d errno %d retval %d duration %d\n",
		  err, errno, retval, duration))
		goto cleanup;

	ASSERT_EQ(atomics_skel->data->and64_value, 0x010ull << 32, "and64_value");
	ASSERT_EQ(atomics_skel->bss->and64_result, 0x110ull << 32, "and64_result");

	ASSERT_EQ(atomics_skel->data->and32_value, 0x010, "and32_value");
	ASSERT_EQ(atomics_skel->bss->and32_result, 0x110, "and32_result");

	ASSERT_EQ(atomics_skel->data->and_noreturn_value, 0x010ull << 32, "and_noreturn_value");
cleanup:
	atomics_test__destroy(atomics_skel);
}

static void test_or(void)
{
	struct atomics_test *atomics_skel;
	int err, prog_fd;
	__u32 duration = 0, retval;

	atomics_skel = setup();
	if (!atomics_skel)
		return;

	prog_fd = bpf_program__fd(atomics_skel->progs.or);
	err = bpf_prog_test_run(prog_fd, 1, NULL, 0,
				NULL, NULL, &retval, &duration);
	if (CHECK(err || retval, "test_run or",
		  "err %d errno %d retval %d duration %d\n",
		  err, errno, retval, duration))
		goto cleanup;

	ASSERT_EQ(atomics_skel->data->or64_value, 0x111ull << 32, "or64_value");
	ASSERT_EQ(atomics_skel->bss->or64_result, 0x110ull << 32, "or64_result");

	ASSERT_EQ(atomics_skel->data->or32_value, 0x111, "or32_value");
	ASSERT_EQ(atomics_skel->bss->or32_result, 0x110, "or32_result");

	ASSERT_EQ(atomics_skel->data->or_noreturn_value, 0x111ull << 32, "or_noreturn_value");
cleanup:
	atomics_test__destroy(atomics_skel);
}

static void test_xor(void)
{
	struct atomics_test *atomics_skel;
	int err, prog_fd;
	__u32 duration = 0, retval;

	atomics_skel = setup();
	if (!atomics_skel)
		return;

	prog_fd = bpf_program__fd(atomics_skel->progs.xor);
	err = bpf_prog_test_run(prog_fd, 1, NULL, 0,
				NULL, NULL, &retval, &duration);
	if (CHECK(err || retval, "test_run xor",
		  "err %d errno %d retval %d duration %d\n",
		  err, errno, retval, duration))
		goto cleanup;

	ASSERT_EQ(atomics_skel->data->xor64_value, 0x101ull << 32, "xor64_value");
	ASSERT_EQ(atomics_skel->bss->xor64_result, 0x110ull << 32, "xor64_result");

	ASSERT_EQ(atomics_skel->data->xor32_value, 0x101, "xor32_value");
	ASSERT_EQ(atomics_skel->bss->xor32_result, 0x110, "xor32_result");

	ASSERT_EQ(atomics_skel->data->xor_noreturn_value, 0x101ull << 32, "xor_nxoreturn_value");
cleanup:
	atomics_test__destroy(atomics_skel);
}

static void test_cmpxchg(void)
{
	struct atomics_test *atomics_skel;
	int err, prog_fd;
	__u32 duration = 0, retval;

	atomics_skel = setup();
	if (!atomics_skel)
		return;

	prog_fd = bpf_program__fd(atomics_skel->progs.add);
	err = bpf_prog_test_run(prog_fd, 1, NULL, 0,
				NULL, NULL, &retval, &duration);
	if (CHECK(err || retval, "test_run add",
		  "err %d errno %d retval %d duration %d\n",
		  err, errno, retval, duration))
		goto cleanup;

	ASSERT_EQ(atomics_skel->data->cmpxchg64_value, 2, "cmpxchg64_value");
	ASSERT_EQ(atomics_skel->bss->cmpxchg64_result_fail, 1, "cmpxchg_result_fail");
	ASSERT_EQ(atomics_skel->bss->cmpxchg64_result_succeed, 1, "cmpxchg_result_succeed");

	ASSERT_EQ(atomics_skel->data->cmpxchg32_value, 2, "cmpxchg32_value");
	ASSERT_EQ(atomics_skel->bss->cmpxchg32_result_fail, 1, "cmpxchg_result_fail");
	ASSERT_EQ(atomics_skel->bss->cmpxchg32_result_succeed, 1, "cmpxchg_result_succeed");

cleanup:
	atomics_test__destroy(atomics_skel);
}

static void test_xchg(void)
{
	struct atomics_test *atomics_skel;
	int err, prog_fd;
	__u32 duration = 0, retval;

	atomics_skel = setup();
	if (!atomics_skel)
		return;

	prog_fd = bpf_program__fd(atomics_skel->progs.add);
	err = bpf_prog_test_run(prog_fd, 1, NULL, 0,
				NULL, NULL, &retval, &duration);
	if (CHECK(err || retval, "test_run add",
		  "err %d errno %d retval %d duration %d\n",
		  err, errno, retval, duration))
		goto cleanup;

	ASSERT_EQ(atomics_skel->data->xchg64_value, 2, "xchg64_value");
	ASSERT_EQ(atomics_skel->bss->xchg64_result, 1, "xchg_result");

	ASSERT_EQ(atomics_skel->data->xchg32_value, 2, "xchg32_value");
	ASSERT_EQ(atomics_skel->bss->xchg32_result, 1, "xchg_result");

cleanup:
	atomics_test__destroy(atomics_skel);
}

void test_atomics_test(void)
{
	if (test__start_subtest("add"))
		test_add();
	if (test__start_subtest("sub"))
		test_sub();
	if (test__start_subtest("and"))
		test_and();
	if (test__start_subtest("or"))
		test_or();
	if (test__start_subtest("xor"))
		test_xor();
	if (test__start_subtest("cmpxchg"))
		test_cmpxchg();
	if (test__start_subtest("xchg"))
		test_xchg();
}
