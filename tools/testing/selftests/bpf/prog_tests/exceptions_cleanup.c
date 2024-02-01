#include "bpf/bpf.h"
#include "exceptions.skel.h"
#include <test_progs.h>
#include <network_helpers.h>

#include "exceptions_cleanup.skel.h"
#include "exceptions_cleanup_fail.skel.h"

static void test_exceptions_cleanup_fail(void)
{
	RUN_TESTS(exceptions_cleanup_fail);
}

void test_exceptions_cleanup(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, ropts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.repeat = 1,
	);
	struct exceptions_cleanup *skel;
	int ret;

	if (test__start_subtest("exceptions_cleanup_fail"))
		test_exceptions_cleanup_fail();

	skel = exceptions_cleanup__open_and_load();
	if (!ASSERT_OK_PTR(skel, "exceptions_cleanup__open_and_load"))
		return;

	ret = exceptions_cleanup__attach(skel);
	if (!ASSERT_OK(ret, "exceptions_cleanup__attach"))
		return;

#define RUN_EXC_CLEANUP_TEST(name)                                      \
	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.name), \
				     &ropts);                           \
	if (!ASSERT_OK(ret, #name ": return value"))                    \
		return;                                                 \
	if (!ASSERT_EQ(ropts.retval, 0xeB9F, #name ": opts.retval"))    \
		return;                                                 \
	ret = bpf_prog_test_run_opts(                                   \
		bpf_program__fd(skel->progs.exceptions_cleanup_check),  \
		&ropts);                                                \
	if (!ASSERT_OK(ret, #name " CHECK: return value"))              \
		return;                                                 \
	if (!ASSERT_EQ(ropts.retval, 0, #name " CHECK: opts.retval"))   \
		return;													\
	skel->bss->only_count = 0;

	RUN_EXC_CLEANUP_TEST(exceptions_cleanup_prog_num_iter);
	RUN_EXC_CLEANUP_TEST(exceptions_cleanup_prog_num_iter_mult);
	RUN_EXC_CLEANUP_TEST(exceptions_cleanup_prog_dynptr_iter);
	RUN_EXC_CLEANUP_TEST(exceptions_cleanup_obj);
	RUN_EXC_CLEANUP_TEST(exceptions_cleanup_percpu_obj);
	RUN_EXC_CLEANUP_TEST(exceptions_cleanup_ringbuf);
	RUN_EXC_CLEANUP_TEST(exceptions_cleanup_reg);
	RUN_EXC_CLEANUP_TEST(exceptions_cleanup_null_or_ptr_do_ptr);
	RUN_EXC_CLEANUP_TEST(exceptions_cleanup_null_or_ptr_do_null);
	RUN_EXC_CLEANUP_TEST(exceptions_cleanup_callee_saved);
	RUN_EXC_CLEANUP_TEST(exceptions_cleanup_frame);
	RUN_EXC_CLEANUP_TEST(exceptions_cleanup_loop_iterations);
	RUN_EXC_CLEANUP_TEST(exceptions_cleanup_dead_code_elim);
	RUN_EXC_CLEANUP_TEST(exceptions_cleanup_frame_dce);
}
