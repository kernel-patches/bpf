// SPDX-License-Identifier: GPL-2.0

#include <unistd.h>
#include <test_progs.h>
#include "inode_build_id.skel.h"
#include "trace_helpers.h"

void test_inode_build_id(void)
{
	int go[2], err, child_pid, child_status, c = 1, sz;
	char build_id[BPF_BUILD_ID_SIZE];
	struct inode_build_id *skel;

	skel = inode_build_id__open_and_load();
	if (!ASSERT_OK_PTR(skel, "inode_build_id__open_and_load"))
		return;

	if (!ASSERT_OK(pipe(go), "pipe"))
		goto out;

	child_pid = fork();
	if (child_pid < 0)
		goto out;

	/* child */
	if (child_pid == 0) {
		/* wait for parent's pid update */
		err = read(go[0], &c, 1);
		if (!ASSERT_EQ(err, 1, "child_read_pipe"))
			exit(err);

		execle("./urandom_read", "urandom_read", NULL, NULL);
		exit(errno);
	}

	/* parent, update child's pid and kick it */
	skel->bss->pid = child_pid;

	err = inode_build_id__attach(skel);
	if (!ASSERT_OK(err, "inode_build_id__attach"))
		goto out;

	err = write(go[1], &c, 1);
	if (!ASSERT_EQ(err, 1, "child_write_pipe"))
		goto out;

	/* wait for child to exit */
	waitpid(child_pid, &child_status, 0);
	if (!ASSERT_EQ(WEXITSTATUS(child_status), 0, "child_exit_value"))
		goto out;

	sz = read_build_id("./urandom_read", build_id);
	if (!ASSERT_GT(sz, 0, "read_build_id"))
		goto out;

	ASSERT_EQ(skel->bss->build_id_bin_size, sz, "build_id_bin_size");
	ASSERT_MEMEQ(skel->bss->build_id_bin, build_id, sz, "build_id_bin");

	sz = read_build_id("./liburandom_read.so", build_id);
	if (!ASSERT_GT(sz, 0, "read_build_id"))
		goto out;

	ASSERT_EQ(skel->bss->build_id_lib_size, sz, "build_id_lib_size");
	ASSERT_MEMEQ(skel->bss->build_id_lib, build_id, sz, "build_id_lib");

out:
	inode_build_id__destroy(skel);
}
