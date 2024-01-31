// SPDX-License-Identifier: GPL-2.0
/* Copyright Leon Hwang */

#include <test_progs.h>

/* test_ffs64 tests the generic kfunc bpf_ffs64().
 */
static void test_ffs64(void)
{
	struct bpf_object *obj = NULL;
	struct bpf_program *prog;
	char buff[128] = {};
	int err, prog_fd;

	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = buff,
		.data_size_in = sizeof(buff),
		.repeat = 1,
	);

	err = bpf_prog_test_load("bitops.bpf.o", BPF_PROG_TYPE_SCHED_CLS, &obj,
				 &prog_fd);
	if (!ASSERT_OK(err, "load obj"))
		return;

	prog = bpf_object__find_program_by_name(obj, "tc_ffs64");
	if (!ASSERT_OK_PTR(prog, "find tc_ffs64"))
		goto out;

#define TEST_FFS(n)						\
	do {							\
		u64 __n = 1;					\
								\
		*(u64 *)(void *) buff = (u64) (__n << n);	\
		err = bpf_prog_test_run_opts(prog_fd, &topts);	\
		ASSERT_OK(err, "run prog");			\
		ASSERT_EQ(topts.retval, n, "run prog");		\
	} while (0)

	TEST_FFS(0);
	TEST_FFS(1);
	TEST_FFS(31);
	TEST_FFS(63);

#undef TEST_FFS
out:
	bpf_object__close(obj);
}

void test_bitops(void)
{
	if (test__start_subtest("bitops_ffs64"))
		test_ffs64();
}
