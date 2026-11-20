// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "func_args_core.skel.h"
#include "func_args_core.lskel.h"

/* runs bpf_fentry_test1..N() (via a fentry prog), bpf_modify_return_test()
 * (via a fmod_ret prog) and bpf_testmod's test read
 */
static void trigger(int fentry_prog_fd, int fmod_ret_prog_fd)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts);

	ASSERT_OK(bpf_prog_test_run_opts(fentry_prog_fd, &topts), "test_run");
	ASSERT_OK(bpf_prog_test_run_opts(fmod_ret_prog_fd, &topts), "test_run_fmod_ret");
	ASSERT_OK(trigger_module_test_read(256), "trigger_read");
}

/* the skeleton and light skeleton have identically named bss/data members */
#define check_results(skel) ({							\
	ASSERT_EQ(skel->bss->t3_a, 4, "t3_a");					\
	ASSERT_EQ(skel->bss->t3_b, 5, "t3_b");					\
	ASSERT_EQ(skel->bss->t3_c, 6, "t3_c");					\
	ASSERT_EQ(skel->bss->t3_b_alias, 5, "t3_b_alias");			\
	ASSERT_EQ(skel->data->t3_missing_exists, 0, "t3_missing_exists");	\
	ASSERT_EQ(skel->data->t3_bad_type_exists, 0, "t3_bad_type_exists");	\
	ASSERT_EQ(skel->data->t3_missing_flavor_exists, 0, "t3_missing_flavor_exists"); \
	ASSERT_EQ(skel->data->t3_fentry_ret_exists, 0, "t3_fentry_ret_exists"); \
	ASSERT_EQ(skel->data->t3_ret_exists, 1, "t3_ret_exists");		\
	ASSERT_EQ(skel->bss->t3_ret, 15, "t3_ret");				\
										\
	ASSERT_EQ(skel->bss->fm_calls, 1, "fm_calls");				\
	ASSERT_EQ(skel->bss->fm_a, 1, "fm_a");					\
	ASSERT_TRUE(skel->bss->fm_b_set, "fm_b_set");				\
	ASSERT_EQ(skel->data->fm_ret, 0, "fm_ret");				\
	ASSERT_EQ(skel->data->fm_ret_exists, 1, "fm_ret_exists");		\
	ASSERT_EQ(skel->data->fm_missing_exists, 0, "fm_missing_exists");	\
										\
	ASSERT_EQ(skel->data->fs_ret_exists, 1, "fs_ret_exists");		\
	ASSERT_EQ(skel->bss->fs_entry_calls, 1, "fs_entry_calls");		\
	ASSERT_EQ(skel->bss->fs_exit_calls, 1, "fs_exit_calls");		\
	ASSERT_EQ(skel->bss->fs_entry_c, 6, "fs_entry_c");			\
	ASSERT_EQ(skel->bss->fs_exit_c, 6, "fs_exit_c");			\
	ASSERT_EQ(skel->data->fs_entry_ret, 0, "fs_entry_ret");		\
	ASSERT_EQ(skel->data->fs_exit_ret, 15, "fs_exit_ret");			\
										\
	ASSERT_EQ(skel->bss->m3_a, 4, "m3_a");					\
	ASSERT_EQ(skel->bss->m3_b, 5, "m3_b");					\
	ASSERT_EQ(skel->bss->m3_c, 6, "m3_c");					\
	ASSERT_EQ(skel->data->m3_missing, 0, "m3_missing");			\
	ASSERT_EQ(skel->data->m3_missing_exists, 0, "m3_missing_exists");	\
	ASSERT_EQ(skel->bss->m3_ret, 15, "m3_ret");				\
	ASSERT_EQ(skel->data->m3_ret_exists, 1, "m3_ret_exists");		\
										\
	ASSERT_EQ(skel->bss->mf_b, 5, "mf_b");					\
	ASSERT_EQ(skel->data->mf_ret, 0, "mf_ret");				\
	ASSERT_EQ(skel->data->mf_ret_exists, 0, "mf_ret_exists");		\
	ASSERT_EQ(skel->data->mf_a, 0, "mf_a");					\
	ASSERT_EQ(skel->data->mf_a_exists, 0, "mf_a_exists");			\
										\
	ASSERT_EQ(skel->bss->s1_a_a, 2, "s1_a_a");				\
	ASSERT_EQ(skel->bss->s1_a_b, 3, "s1_a_b");				\
	ASSERT_EQ(skel->bss->s1_b, 1, "s1_b");					\
	ASSERT_EQ(skel->bss->s1_c, 4, "s1_c");					\
	ASSERT_EQ(skel->bss->s1_ret, 10, "s1_ret");				\
										\
	ASSERT_EQ(skel->bss->tp_pid, getpid(), "tp_pid");			\
	ASSERT_EQ(skel->bss->tp_len, 256, "tp_len");				\
	ASSERT_EQ(skel->data->tp_bad_ptr_exists, 0, "tp_bad_ptr_exists");	\
	ASSERT_EQ(skel->data->tp_fwd_exists, 1, "tp_fwd_exists");		\
	ASSERT_EQ(skel->data->tp_void_exists, 1, "tp_void_exists");		\
	ASSERT_EQ(skel->data->tp_void_same, 1, "tp_void_same");		\
	ASSERT_EQ(skel->bss->mtp_pid, getpid(), "mtp_pid");			\
})

/* CO-RE relocations applied by libbpf */
static void test_skel(void)
{
	struct func_args_core *skel;

	skel = func_args_core__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		return;
	if (!ASSERT_OK(func_args_core__attach(skel), "skel_attach"))
		goto cleanup;

	trigger(bpf_program__fd(skel->progs.fentry3),
		bpf_program__fd(skel->progs.fmod_ret_test));
	check_results(skel);
cleanup:
	func_args_core__destroy(skel);
}

/* CO-RE relocations applied by the kernel */
static void test_lskel(void)
{
	struct func_args_core_lskel *skel;

	skel = func_args_core_lskel__open_and_load();
	if (!ASSERT_OK_PTR(skel, "lskel_open_and_load"))
		return;
	if (!ASSERT_OK(func_args_core_lskel__attach(skel), "lskel_attach"))
		goto cleanup;

	trigger(skel->progs.fentry3.prog_fd, skel->progs.fmod_ret_test.prog_fd);
	check_results(skel);
cleanup:
	func_args_core_lskel__destroy(skel);
}

void test_func_args_core(void)
{
	if (test__start_subtest("skel"))
		test_skel();
	if (test__start_subtest("lskel"))
		test_lskel();
}
