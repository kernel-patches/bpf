// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>

#ifdef ENABLE_ATOMICS_TESTS

#include "atomics_test.skel.h"

static void test_add(void)
{
	struct atomics_test *atomics_skel = NULL;
	int err, prog_fd;
	__u32 duration = 0, retval;

	atomics_skel = atomics_test__open_and_load();
	if (CHECK(!atomics_skel, "atomics_skel_load", "atomics skeleton failed\n"))
		goto cleanup;

	err = atomics_test__attach(atomics_skel);
	if (CHECK(err, "atomics_attach", "atomics attach failed: %d\n", err))
		goto cleanup;

	prog_fd = bpf_program__fd(atomics_skel->progs.add);
	err = bpf_prog_test_run(prog_fd, 1, NULL, 0,
				NULL, NULL, &retval, &duration);
	if (CHECK(err || retval, "test_run add",
		  "err %d errno %d retval %d duration %d\n",
		  err, errno, retval, duration))
		goto cleanup;

	CHECK(atomics_skel->data->add64_value != 3, "add64_value",
	      "64bit atomic add value was not incremented (got %lld want 2)\n",
	      atomics_skel->data->add64_value);
	CHECK(atomics_skel->bss->add64_result != 1, "add64_result",
	      "64bit atomic add bad return value (got %lld want 1)\n",
	      atomics_skel->bss->add64_result);

	CHECK(atomics_skel->data->add32_value != 3, "add32_value",
	      "32bit atomic add value was not incremented (got %d want 2)\n",
	      atomics_skel->data->add32_value);
	CHECK(atomics_skel->bss->add32_result != 1, "add32_result",
	      "32bit atomic add bad return value (got %d want 1)\n",
	      atomics_skel->bss->add32_result);

	CHECK(atomics_skel->bss->add_stack_value_copy != 3, "add_stack_value",
	      "stack atomic add value was not incremented (got %lld want 2)\n",
	      atomics_skel->bss->add_stack_value_copy);
	CHECK(atomics_skel->bss->add_stack_result != 1, "add_stack_result",
	      "stack atomic add bad return value (got %lld want 1)\n",
	      atomics_skel->bss->add_stack_result);

cleanup:
	atomics_test__destroy(atomics_skel);
}

static void test_sub(void)
{
	struct atomics_test *atomics_skel = NULL;
	int err, prog_fd;
	__u32 duration = 0, retval;

	atomics_skel = atomics_test__open_and_load();
	if (CHECK(!atomics_skel, "atomics_skel_load", "atomics skeleton failed\n"))
		goto cleanup;

	err = atomics_test__attach(atomics_skel);
	if (CHECK(err, "atomics_attach", "atomics attach failed: %d\n", err))
		goto cleanup;

	prog_fd = bpf_program__fd(atomics_skel->progs.sub);
	err = bpf_prog_test_run(prog_fd, 1, NULL, 0,
				NULL, NULL, &retval, &duration);
	if (CHECK(err || retval, "test_run sub",
		  "err %d errno %d retval %d duration %d\n",
		  err, errno, retval, duration))
		goto cleanup;

	CHECK(atomics_skel->data->sub64_value != -1, "sub64_value",
	      "64bit atomic sub value was not decremented (got %lld want -1)\n",
	      atomics_skel->data->sub64_value);
	CHECK(atomics_skel->bss->sub64_result != 1, "sub64_result",
	      "64bit atomic sub bad return value (got %lld want 1)\n",
	      atomics_skel->bss->sub64_result);

	CHECK(atomics_skel->data->sub32_value != -1, "sub32_value",
	      "32bit atomic sub value was not decremented (got %d want -1)\n",
	      atomics_skel->data->sub32_value);
	CHECK(atomics_skel->bss->sub32_result != 1, "sub32_result",
	      "32bit atomic sub bad return value (got %d want 1)\n",
	      atomics_skel->bss->sub32_result);

	CHECK(atomics_skel->bss->sub_stack_value_copy != -1, "sub_stack_value",
	      "stack atomic sub value was not decremented (got %lld want -1)\n",
	      atomics_skel->bss->sub_stack_value_copy);
	CHECK(atomics_skel->bss->sub_stack_result != 1, "sub_stack_result",
	      "stack atomic sub bad return value (got %lld want 1)\n",
	      atomics_skel->bss->sub_stack_result);

cleanup:
	atomics_test__destroy(atomics_skel);
}

static void test_and(void)
{
	struct atomics_test *atomics_skel = NULL;
	int err, prog_fd;
	__u32 duration = 0, retval;

	atomics_skel = atomics_test__open_and_load();
	if (CHECK(!atomics_skel, "atomics_skel_load", "atomics skeleton failed\n"))
		goto cleanup;

	err = atomics_test__attach(atomics_skel);
	if (CHECK(err, "atomics_attach", "atomics attach failed: %d\n", err))
		goto cleanup;

	prog_fd = bpf_program__fd(atomics_skel->progs.and);
	err = bpf_prog_test_run(prog_fd, 1, NULL, 0,
				NULL, NULL, &retval, &duration);
	if (CHECK(err || retval, "test_run and",
		  "err %d errno %d retval %d duration %d\n",
		  err, errno, retval, duration))
		goto cleanup;

	CHECK(atomics_skel->data->and64_value != 0x010ull << 32, "and64_value",
	      "64bit atomic and, bad value (got 0x%llx want 0x%llx)\n",
	      atomics_skel->data->and64_value, 0x010ull << 32);
	CHECK(atomics_skel->bss->and64_result != 0x110ull << 32, "and64_result",
	      "64bit atomic and, bad result (got 0x%llx want 0x%llx)\n",
	      atomics_skel->bss->and64_result, 0x110ull << 32);

	CHECK(atomics_skel->data->and32_value != 0x010, "and32_value",
	      "32bit atomic and, bad value (got 0x%x want 0x%x)\n",
	      atomics_skel->data->and32_value, 0x010);
	CHECK(atomics_skel->bss->and32_result != 0x110, "and32_result",
	      "32bit atomic and, bad result (got 0x%x want 0x%x)\n",
	      atomics_skel->bss->and32_result, 0x110);

cleanup:
	atomics_test__destroy(atomics_skel);
}

static void test_or(void)
{
	struct atomics_test *atomics_skel = NULL;
	int err, prog_fd;
	__u32 duration = 0, retval;

	atomics_skel = atomics_test__open_and_load();
	if (CHECK(!atomics_skel, "atomics_skel_load", "atomics skeleton failed\n"))
		goto cleanup;

	err = atomics_test__attach(atomics_skel);
	if (CHECK(err, "atomics_attach", "atomics attach failed: %d\n", err))
		goto cleanup;

	prog_fd = bpf_program__fd(atomics_skel->progs.or);
	err = bpf_prog_test_run(prog_fd, 1, NULL, 0,
				NULL, NULL, &retval, &duration);
	if (CHECK(err || retval, "test_run or",
		  "err %d errno %d retval %d duration %d\n",
		  err, errno, retval, duration))
		goto cleanup;

	CHECK(atomics_skel->data->or64_value != 0x111ull << 32, "or64_value",
	      "64bit atomic or, bad value (got 0x%llx want 0x%llx)\n",
	      atomics_skel->data->or64_value, 0x111ull << 32);
	CHECK(atomics_skel->bss->or64_result != 0x110ull << 32, "or64_result",
	      "64bit atomic or, bad result (got 0x%llx want 0x%llx)\n",
	      atomics_skel->bss->or64_result, 0x110ull << 32);

	CHECK(atomics_skel->data->or32_value != 0x111, "or32_value",
	      "32bit atomic or, bad value (got 0x%x want 0x%x)\n",
	      atomics_skel->data->or32_value, 0x111);
	CHECK(atomics_skel->bss->or32_result != 0x110, "or32_result",
	      "32bit atomic or, bad result (got 0x%x want 0x%x)\n",
	      atomics_skel->bss->or32_result, 0x110);

cleanup:
	atomics_test__destroy(atomics_skel);
}

static void test_xor(void)
{
	struct atomics_test *atomics_skel = NULL;
	int err, prog_fd;
	__u32 duration = 0, retval;

	atomics_skel = atomics_test__open_and_load();
	if (CHECK(!atomics_skel, "atomics_skel_load", "atomics skeleton failed\n"))
		goto cleanup;

	err = atomics_test__attach(atomics_skel);
	if (CHECK(err, "atomics_attach", "atomics attach failed: %d\n", err))
		goto cleanup;

	prog_fd = bpf_program__fd(atomics_skel->progs.xor);
	err = bpf_prog_test_run(prog_fd, 1, NULL, 0,
				NULL, NULL, &retval, &duration);
	if (CHECK(err || retval, "test_run xor",
		  "err %d errno %d retval %d duration %d\n",
		  err, errno, retval, duration))
		goto cleanup;

	CHECK(atomics_skel->data->xor64_value != 0x101ull << 32, "xor64_value",
	      "64bit atomic xor, bad value (got 0x%llx want 0x%llx)\n",
	      atomics_skel->data->xor64_value, 0x101ull << 32);
	CHECK(atomics_skel->bss->xor64_result != 0x110ull << 32, "xor64_result",
	      "64bit atomic xor, bad result (got 0x%llx want 0x%llx)\n",
	      atomics_skel->bss->xor64_result, 0x110ull << 32);

	CHECK(atomics_skel->data->xor32_value != 0x101, "xor32_value",
	      "32bit atomic xor, bad value (got 0x%x want 0x%x)\n",
	      atomics_skel->data->xor32_value, 0x101);
	CHECK(atomics_skel->bss->xor32_result != 0x110, "xor32_result",
	      "32bit atomic xor, bad result (got 0x%x want 0x%x)\n",
	      atomics_skel->bss->xor32_result, 0x110);

cleanup:
	atomics_test__destroy(atomics_skel);
}

static void test_cmpxchg(void)
{
	struct atomics_test *atomics_skel = NULL;
	int err, prog_fd;
	__u32 duration = 0, retval;

	atomics_skel = atomics_test__open_and_load();
	if (CHECK(!atomics_skel, "atomics_skel_load", "atomics skeleton failed\n"))
		goto cleanup;

	err = atomics_test__attach(atomics_skel);
	if (CHECK(err, "atomics_attach", "atomics attach failed: %d\n", err))
		goto cleanup;

	prog_fd = bpf_program__fd(atomics_skel->progs.add);
	err = bpf_prog_test_run(prog_fd, 1, NULL, 0,
				NULL, NULL, &retval, &duration);
	if (CHECK(err || retval, "test_run add",
		  "err %d errno %d retval %d duration %d\n",
		  err, errno, retval, duration))
		goto cleanup;

	CHECK(atomics_skel->data->cmpxchg64_value != 2, "cmpxchg64_value",
	      "64bit cmpxchg left unexpected value (got %llx want 2)\n",
	      atomics_skel->data->cmpxchg64_value);
	CHECK(atomics_skel->bss->cmpxchg64_result_fail != 1, "cmpxchg_result_fail",
	      "64bit cmpxchg returned bad result (got %llx want 1)\n",
	      atomics_skel->bss->cmpxchg64_result_fail);
	CHECK(atomics_skel->bss->cmpxchg64_result_succeed != 1, "cmpxchg_result_succeed",
	      "64bit cmpxchg returned bad result (got %llx want 1)\n",
	      atomics_skel->bss->cmpxchg64_result_succeed);

	CHECK(atomics_skel->data->cmpxchg32_value != 2, "cmpxchg32_value",
	      "32bit cmpxchg left unexpected value (got %d want 2)\n",
	      atomics_skel->data->cmpxchg32_value);
	CHECK(atomics_skel->bss->cmpxchg32_result_fail != 1, "cmpxchg_result_fail",
	      "32bit cmpxchg returned bad result (got %d want 1)\n",
	      atomics_skel->bss->cmpxchg32_result_fail);
	CHECK(atomics_skel->bss->cmpxchg32_result_succeed != 1, "cmpxchg_result_succeed",
	      "32bit cmpxchg returned bad result (got %d want 1)\n",
	      atomics_skel->bss->cmpxchg32_result_succeed);

cleanup:
	atomics_test__destroy(atomics_skel);
}

static void test_xchg(void)
{
	struct atomics_test *atomics_skel = NULL;
	int err, prog_fd;
	__u32 duration = 0, retval;

	atomics_skel = atomics_test__open_and_load();
	if (CHECK(!atomics_skel, "atomics_skel_load", "atomics skeleton failed\n"))
		goto cleanup;

	err = atomics_test__attach(atomics_skel);
	if (CHECK(err, "atomics_attach", "atomics attach failed: %d\n", err))
		goto cleanup;

	prog_fd = bpf_program__fd(atomics_skel->progs.add);
	err = bpf_prog_test_run(prog_fd, 1, NULL, 0,
				NULL, NULL, &retval, &duration);
	if (CHECK(err || retval, "test_run add",
		  "err %d errno %d retval %d duration %d\n",
		  err, errno, retval, duration))
		goto cleanup;

	CHECK(atomics_skel->data->xchg64_value != 2, "xchg64_value",
	      "64bit xchg left unexpected value (got %lld want 2)\n",
	      atomics_skel->data->xchg64_value);
	CHECK(atomics_skel->bss->xchg64_result != 1, "xchg_result",
	      "64bit xchg returned bad result (got %lld want 1)\n",
	      atomics_skel->bss->xchg64_result);

	CHECK(atomics_skel->data->xchg32_value != 2, "xchg32_value",
	      "32bit xchg left unexpected value (got %d want 2)\n",
	      atomics_skel->data->xchg32_value);
	CHECK(atomics_skel->bss->xchg32_result != 1, "xchg_result",
	      "32bit xchg returned bad result (got %d want 1)\n",
	      atomics_skel->bss->xchg32_result);

cleanup:
	atomics_test__destroy(atomics_skel);
}

void test_atomics_test(void)
{
	test_add();
	test_sub();
	test_and();
	test_or();
	test_xor();
	test_cmpxchg();
	test_xchg();
}

#else /* ENABLE_ATOMICS_TESTS */

void test_atomics_test(void)
{
	printf("%s:SKIP:no ENABLE_ATOMICS_TEST (missing Clang BPF atomics support)",
	       __func__);
	test__skip();
}

#endif /* ENABLE_ATOMICS_TESTS */
