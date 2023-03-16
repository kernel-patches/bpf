// SPDX-License-Identifier: GPL-2.0

#include <unistd.h>
#include <test_progs.h>
#include "file_build_id.skel.h"
#include "trace_helpers.h"

static void
test_build_id(const char *bin, const char *lib, long bin_err, long lib_err)
{
	int err, child_pid = 0, child_status, c = 1, sz;
	char build_id[BPF_BUILD_ID_SIZE];
	struct file_build_id *skel;
	int go[2] = { -1, -1 };

	if (!ASSERT_OK(pipe(go), "pipe"))
		return;

	skel = file_build_id__open_and_load();
	if (!ASSERT_OK_PTR(skel, "file_build_id__open_and_load"))
		goto out;

	child_pid = fork();
	if (child_pid < 0)
		goto out;

	/* child */
	if (child_pid == 0) {
		close(go[1]);
		/* wait for parent's pid update */
		err = read(go[0], &c, 1);
		if (!ASSERT_EQ(err, 1, "child_read_pipe"))
			exit(err);

		execle(bin, bin, NULL, NULL);
		exit(errno);
	}

	/* parent, update child's pid and kick it */
	skel->bss->pid = child_pid;

	close(go[0]);

	err = file_build_id__attach(skel);
	if (!ASSERT_OK(err, "file_build_id__attach"))
		goto out;

	err = write(go[1], &c, 1);
	if (!ASSERT_EQ(err, 1, "child_write_pipe"))
		goto out;

	/* wait for child to exit */
	waitpid(child_pid, &child_status, 0);
	child_pid = 0;
	if (!ASSERT_EQ(WEXITSTATUS(child_status), 0, "child_exit_value"))
		goto out;

	/* test binary */
	sz = read_build_id(bin, build_id);
	err = sz > 0 ? 0 : sz;

	ASSERT_EQ((long) err, bin_err, "read_build_id_bin_err");
	ASSERT_EQ(skel->bss->build_id_bin_err, bin_err, "build_id_bin_err");

	if (!err) {
		ASSERT_EQ(skel->bss->build_id_bin_size, sz, "build_id_bin_size");
		ASSERT_MEMEQ(skel->bss->build_id_bin, build_id, sz, "build_id_bin");
	}

	/* test library if present */
	if (lib) {
		sz = read_build_id(lib, build_id);
		err = sz > 0 ? 0 : sz;

		ASSERT_EQ((long) err, lib_err, "read_build_id_lib_err");
		ASSERT_EQ(skel->bss->build_id_lib_err, lib_err, "build_id_lib_err");

		if (!err) {
			ASSERT_EQ(skel->bss->build_id_lib_size, sz, "build_id_lib_size");
			ASSERT_MEMEQ(skel->bss->build_id_lib, build_id, sz, "build_id_lib");
		}
	}

out:
	close(go[1]);
	close(go[0]);
	if (child_pid)
		waitpid(child_pid, &child_status, 0);
	file_build_id__destroy(skel);
}

void test_file_build_id(void)
{
	if (test__start_subtest("present"))
		test_build_id("./urandom_read", "./liburandom_read.so", 0, 0);
	if (test__start_subtest("missing"))
		test_build_id("./no_build_id", NULL, -EINVAL, 0);
}
