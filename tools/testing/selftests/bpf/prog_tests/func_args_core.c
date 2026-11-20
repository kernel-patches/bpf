// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "func_args_core.skel.h"
#include "func_args_core.lskel.h"
#include "func_args_core_lsm.skel.h"
#include "func_args_core_lsm.lskel.h"
#include "func_args_core_lsm_cgroup.skel.h"
#include "func_args_core_lsm_cgroup.lskel.h"
#include "cgroup_helpers.h"
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>

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
	ASSERT_EQ(skel->data->t3_supported, 1, "t3_supported");		\
	ASSERT_EQ(skel->data->t3_untagged_supported, 0, "t3_untagged_supported"); \
	ASSERT_EQ(skel->data->m3_supported, 1, "m3_supported");		\
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

/* An ioctl command that no file implements: the call fails after the
 * file_ioctl hook ran, so whatever the programs return has no effect on the
 * process (unlike, e.g., an mprotect() that they allow). Its top bit is set
 * to check that the unsigned int argument isn't sign-extended.
 */
#define LSM_IOCTL_CMD	0xb1f0c0deU
#define LSM_IOCTL_ARG	0x0123456789abcdefULL

/* Run file_ioctl(file, cmd, arg) for an ioctl() on a memfd, only monitoring
 * that call; returns the memfd's inode number, or 0 on failure.
 */
static __u64 lsm_ioctl(int *monitored_pid)
{
	struct stat st;
	__u64 ino = 0;
	int fd, err;

	fd = memfd_create("func_args_core", MFD_CLOEXEC);
	if (!ASSERT_OK_FD(fd, "memfd_create"))
		return 0;
	if (!ASSERT_OK(fstat(fd, &st), "fstat"))
		goto out;

	*monitored_pid = getpid();
	err = ioctl(fd, LSM_IOCTL_CMD, LSM_IOCTL_ARG) ? -errno : 0;
	*monitored_pid = 0;

	if (ASSERT_EQ(err, -ENOTTY, "ioctl"))
		ino = st.st_ino;
out:
	close(fd);
	return ino;
}

/* file_ioctl(file, cmd, arg) via lsm_ioctl() */
#define check_lsm_results(skel, ino) ({					\
	ASSERT_EQ(skel->bss->s_calls, 1, "s_calls");				\
	ASSERT_EQ(skel->bss->s_arg, LSM_IOCTL_ARG, "s_arg");			\
	ASSERT_EQ(skel->bss->s_ino, ino, "s_ino");				\
	ASSERT_EQ(skel->data->s_ret, 0, "s_ret");				\
	ASSERT_EQ(skel->data->s_ret_exists, 1, "s_ret_exists");		\
	ASSERT_EQ(skel->data->s_added_exists, 0, "s_added_exists");		\
	ASSERT_EQ(skel->data->s_supported, 1, "s_supported");			\
	ASSERT_EQ(skel->data->m_supported, 1, "m_supported");			\
										\
	/* file___new (struct vfs_file *) doesn't match, file is used instead */ \
	ASSERT_EQ(skel->data->v_new_exists, 0, "v_new_exists");		\
	ASSERT_EQ(skel->data->v_old_exists, 1, "v_old_exists");		\
	ASSERT_EQ(skel->bss->v_ino, ino, "v_ino");				\
	ASSERT_EQ(skel->data->vm_new_exists, 0, "vm_new_exists");		\
	ASSERT_EQ(skel->data->vm_old_exists, 1, "vm_old_exists");		\
	ASSERT_EQ(skel->bss->vm_ino, ino, "vm_ino");				\
										\
	/* only the flavored file___old matches */				\
	ASSERT_EQ(skel->data->o_new_exists, 0, "o_new_exists");		\
	ASSERT_EQ(skel->data->o_old_exists, 1, "o_old_exists");		\
	ASSERT_EQ(skel->bss->o_ino, ino, "o_ino");				\
	ASSERT_EQ(skel->data->om_new_exists, 0, "om_new_exists");		\
	ASSERT_EQ(skel->data->om_old_exists, 1, "om_old_exists");		\
	ASSERT_EQ(skel->bss->om_ino, ino, "om_ino");				\
										\
	ASSERT_EQ(skel->bss->m_calls, 1, "m_calls");				\
	ASSERT_EQ(skel->bss->m_arg, LSM_IOCTL_ARG, "m_arg");			\
	ASSERT_EQ(skel->bss->m_cmd, LSM_IOCTL_CMD, "m_cmd");			\
	ASSERT_EQ(skel->data->m_added, 0, "m_added");				\
	ASSERT_EQ(skel->data->m_added_exists, 0, "m_added_exists");		\
	ASSERT_EQ(skel->data->m_ret, 0, "m_ret");				\
	ASSERT_EQ(skel->data->m_ret_exists, 1, "m_ret_exists");		\
})

static void test_lsm_skel(void)
{
	struct func_args_core_lsm *skel;
	__u64 ino;

	skel = func_args_core_lsm__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		return;
	if (!ASSERT_OK(func_args_core_lsm__attach(skel), "skel_attach"))
		goto cleanup;

	ino = lsm_ioctl(&skel->bss->monitored_pid);
	if (ASSERT_NEQ(ino, 0, "lsm_ioctl"))
		check_lsm_results(skel, ino);
cleanup:
	func_args_core_lsm__destroy(skel);
}

static void test_lsm_lskel(void)
{
	struct func_args_core_lsm_lskel *skel;
	__u64 ino;

	skel = func_args_core_lsm_lskel__open_and_load();
	if (!ASSERT_OK_PTR(skel, "lskel_open_and_load"))
		return;
	if (!ASSERT_OK(func_args_core_lsm_lskel__attach(skel), "lskel_attach"))
		goto cleanup;

	ino = lsm_ioctl(&skel->bss->monitored_pid);
	if (ASSERT_NEQ(ino, 0, "lsm_ioctl"))
		check_lsm_results(skel, ino);
cleanup:
	func_args_core_lsm_lskel__destroy(skel);
}

/* socket_create(family, type, protocol, kern) via socket(AF_UNIX, ...) */
#define check_lsm_cgroup_results(skel) ({					\
	ASSERT_EQ(skel->bss->lc_calls, 1, "lc_calls");				\
	ASSERT_EQ(skel->data->lc_family, AF_UNIX, "lc_family");		\
	ASSERT_EQ(skel->data->lc_protocol, 0, "lc_protocol");			\
	ASSERT_EQ(skel->data->lc_kern, 0, "lc_kern");				\
	ASSERT_EQ(skel->data->lc_ret_exists, 1, "lc_ret_exists");		\
	ASSERT_EQ(skel->data->lc_added_exists, 0, "lc_added_exists");		\
	ASSERT_EQ(skel->data->lc_supported, 1, "lc_supported");		\
})

static void trigger_lsm_cgroup(void)
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);

	if (ASSERT_OK_FD(fd, "socket"))
		close(fd);
}

static void test_lsm_cgroup_skel(void)
{
	struct func_args_core_lsm_cgroup *skel;
	struct bpf_link *link = NULL;
	int cgroup_fd;

	cgroup_fd = test__join_cgroup("/func_args_core");
	if (!ASSERT_OK_FD(cgroup_fd, "join_cgroup"))
		return;

	skel = func_args_core_lsm_cgroup__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		goto out;
	link = bpf_program__attach_cgroup(skel->progs.socket_create_struct, cgroup_fd);
	if (!ASSERT_OK_PTR(link, "attach_cgroup"))
		goto out;

	trigger_lsm_cgroup();
	check_lsm_cgroup_results(skel);
out:
	bpf_link__destroy(link);
	func_args_core_lsm_cgroup__destroy(skel);
	close(cgroup_fd);
}

static void test_lsm_cgroup_lskel(void)
{
	struct func_args_core_lsm_cgroup_lskel *skel;
	int cgroup_fd, link_fd = -1;

	cgroup_fd = test__join_cgroup("/func_args_core");
	if (!ASSERT_OK_FD(cgroup_fd, "join_cgroup"))
		return;

	skel = func_args_core_lsm_cgroup_lskel__open_and_load();
	if (!ASSERT_OK_PTR(skel, "lskel_open_and_load"))
		goto out;
	link_fd = bpf_link_create(skel->progs.socket_create_struct.prog_fd, cgroup_fd,
				  BPF_LSM_CGROUP, NULL);
	if (!ASSERT_OK_FD(link_fd, "link_create"))
		goto out;

	trigger_lsm_cgroup();
	check_lsm_cgroup_results(skel);
out:
	if (link_fd >= 0)
		close(link_fd);
	func_args_core_lsm_cgroup_lskel__destroy(skel);
	close(cgroup_fd);
}

void test_func_args_core(void)
{
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	/* On big-endian targets, the verifier only allows loads of whole
	 * context slots, and loads of signed arguments smaller than 8 bytes
	 * can only be widened to their slot if they are sign-extending. The
	 * programs read signed int arguments and return values with
	 * zero-extending loads (directly and via BPF_PROG_CORE()), which
	 * are poisoned there, so they would fail to load.
	 */
	test__skip();
	return;
#endif
	if (test__start_subtest("skel"))
		test_skel();
	if (test__start_subtest("lskel"))
		test_lskel();
	if (test__start_subtest("lsm_skel"))
		test_lsm_skel();
	if (test__start_subtest("lsm_lskel"))
		test_lsm_lskel();
	if (test__start_subtest("lsm_cgroup_skel"))
		test_lsm_cgroup_skel();
	if (test__start_subtest("lsm_cgroup_lskel"))
		test_lsm_cgroup_lskel();
}
