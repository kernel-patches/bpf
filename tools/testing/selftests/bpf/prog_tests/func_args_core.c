// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "func_args_core.skel.h"
#include "func_args_core.lskel.h"

/*
 * Run the programs of a func_args_core skeleton (libbpf or light) and check
 * what they saw through struct bpf_func_args___xyz.
 */
static void check_func_args(struct func_args_core__bss *bss, int fentry_fd, int fmod_ret_fd)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	int fd;

	bss->pid = getpid();
	bss->tp_nr = __NR_getppid;
	/* calls bpf_fentry_test3(4, 5, 6) */
	ASSERT_OK(bpf_prog_test_run_opts(fentry_fd, &topts), "fentry_run");
	/* calls bpf_modify_return_test2(1, &b, 3, 4, 5, 6, 7) */
	ASSERT_OK(bpf_prog_test_run_opts(fmod_ret_fd, &topts), "fmod_ret_run");
	syscall(__NR_getppid);
	fd = open("/dev/null", O_RDONLY);
	if (fd >= 0)
		close(fd);

	ASSERT_EQ(bss->fentry_a, 4, "fentry_a");
	ASSERT_EQ(bss->fentry_b, 5, "fentry_b");
	ASSERT_EQ(bss->fentry_c, 6, "fentry_c");
	ASSERT_EQ(bss->fentry_nope, 0, "fentry_nope_exists");
	ASSERT_EQ(bss->fentry_ret, 0, "fentry_ret_exists");
	ASSERT_EQ(bss->fexit_c, 6, "fexit_c");
	ASSERT_EQ(bss->fexit_ret, 15, "fexit_ret");
	ASSERT_EQ(bss->fmod_ret_c, 3, "fmod_ret_c");
	ASSERT_EQ(bss->fmod_ret_f, 6, "fmod_ret_f");
	ASSERT_EQ(bss->fmod_ret_g, 7, "fmod_ret_g");
	ASSERT_EQ(bss->fmod_ret_ret, 1, "fmod_ret_ret_exists");
	ASSERT_GE(bss->tp_hits, 1, "tp_btf_id");
	ASSERT_EQ(bss->tp_match, 1, "tp_btf_type_matches");
	ASSERT_EQ(bss->tp_mismatch, 0, "tp_btf_type_mismatch");
	ASSERT_EQ(bss->lsm_inode, 1, "lsm_file");
	ASSERT_EQ(bss->lsm_ret, 1, "lsm_ret");
}

static void test_libbpf(void)
{
	struct func_args_core *skel;

	skel = func_args_core__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;
	if (ASSERT_OK(func_args_core__attach(skel), "attach"))
		check_func_args(skel->bss, bpf_program__fd(skel->progs.fentry),
				bpf_program__fd(skel->progs.fmod_ret));
	func_args_core__destroy(skel);
}

static void test_lskel(void)
{
	struct func_args_core_lskel *skel;

	skel = func_args_core_lskel__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;
	/* not __attach(), which would also attach the unloaded "missing" prog */
	if (!ASSERT_GT(func_args_core_lskel__fentry__attach(skel), 0, "attach_fentry") ||
	    !ASSERT_GT(func_args_core_lskel__fexit__attach(skel), 0, "attach_fexit") ||
	    !ASSERT_GT(func_args_core_lskel__fmod_ret__attach(skel), 0, "attach_fmod_ret") ||
	    !ASSERT_GT(func_args_core_lskel__tp_btf__attach(skel), 0, "attach_tp_btf") ||
	    !ASSERT_GT(func_args_core_lskel__lsm__attach(skel), 0, "attach_lsm"))
		goto out;
	/* the same .bss as for the libbpf skeleton, under another name */
	check_func_args((struct func_args_core__bss *)skel->bss,
			skel->progs.fentry.prog_fd, skel->progs.fmod_ret.prog_fd);
out:
	func_args_core_lskel__destroy(skel);
}

static void test_missing(void)
{
	struct func_args_core *skel;

	skel = func_args_core__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		return;
	bpf_program__set_autoload(skel->progs.missing, true);
	ASSERT_ERR(func_args_core__load(skel), "load");
	func_args_core__destroy(skel);
}

void test_func_args_core(void)
{
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	/*
	 * Arguments smaller than 8 bytes are in the high addresses of their
	 * slot there, where the verifier doesn't allow context loads yet.
	 */
	test__skip();
	return;
#endif
	if (test__start_subtest("libbpf"))
		test_libbpf();
	if (test__start_subtest("lskel"))
		test_lskel();
	if (test__start_subtest("missing"))
		test_missing();
}
