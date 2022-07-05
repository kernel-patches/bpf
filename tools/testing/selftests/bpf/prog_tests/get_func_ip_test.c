// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "get_func_ip_test.skel.h"

/* assume IBT is enabled when kernel configs are not available */
#ifdef HAVE_GENHDR
# include "autoconf.h"
#else
#  define CONFIG_X86_KERNEL_IBT 1
#endif

/* test6 and test7 are x86_64 specific because of the instruction
 * offset, disabling it for all other archs
 *
 * CONFIG_X86_KERNEL_IBT adds endbr instruction at function entry,
 * so disabling test6 and test7, because the offset is hardcoded
 * in program section
 */
#if !defined(__x86_64__) || defined(CONFIG_X86_KERNEL_IBT)
#define DISABLE_OFFSET_ATTACH 1
#endif

void test_get_func_ip_test(void)
{
	struct get_func_ip_test *skel = NULL;
	int err, prog_fd;
	LIBBPF_OPTS(bpf_test_run_opts, topts);

	skel = get_func_ip_test__open();
	if (!ASSERT_OK_PTR(skel, "get_func_ip_test__open"))
		return;

#if defined(DISABLE_OFFSET_ATTACH)
	bpf_program__set_autoload(skel->progs.test6, false);
	bpf_program__set_autoload(skel->progs.test7, false);
#endif

	err = get_func_ip_test__load(skel);
	if (!ASSERT_OK(err, "get_func_ip_test__load"))
		goto cleanup;

	err = get_func_ip_test__attach(skel);
	if (!ASSERT_OK(err, "get_func_ip_test__attach"))
		goto cleanup;

	prog_fd = bpf_program__fd(skel->progs.test1);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(topts.retval, 0, "test_run");

	prog_fd = bpf_program__fd(skel->progs.test5);
	err = bpf_prog_test_run_opts(prog_fd, &topts);

	ASSERT_OK(err, "test_run");

	ASSERT_EQ(skel->bss->test1_result, 1, "test1_result");
	ASSERT_EQ(skel->bss->test2_result, 1, "test2_result");
	ASSERT_EQ(skel->bss->test3_result, 1, "test3_result");
	ASSERT_EQ(skel->bss->test4_result, 1, "test4_result");
	ASSERT_EQ(skel->bss->test5_result, 1, "test5_result");
#if !defined(DISABLE_OFFSET_ATTACH)
	ASSERT_EQ(skel->bss->test6_result, 1, "test6_result");
	ASSERT_EQ(skel->bss->test7_result, 1, "test7_result");
#endif

cleanup:
	get_func_ip_test__destroy(skel);
}
