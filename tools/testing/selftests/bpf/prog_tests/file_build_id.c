// SPDX-License-Identifier: GPL-2.0

#include <unistd.h>
#include <test_progs.h>
#include "file_build_id.skel.h"
#include "trace_helpers.h"

#define BUILDID_STR_SIZE (BPF_BUILD_ID_SIZE*2 + 1)

void test_file_build_id(void)
{
	int go[2], err, child_pid, child_status, c = 1, i;
	char bpf_build_id[BUILDID_STR_SIZE] = {};
	struct file_build_id *skel;
	char *bid = NULL;

	skel = file_build_id__open_and_load();
	if (!ASSERT_OK_PTR(skel, "file_build_id__open_and_load"))
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

		execle("/bin/bash", "bash", "-c", "exit 0", NULL, NULL);
		exit(errno);
	}

	/* parent, update child's pid and kick it */
	skel->bss->pid = child_pid;

	err = file_build_id__attach(skel);
	if (!ASSERT_OK(err, "file_build_id__attach"))
		goto out;

	err = write(go[1], &c, 1);
	if (!ASSERT_EQ(err, 1, "child_write_pipe"))
		goto out;

	/* wait for child to exit */
	waitpid(child_pid, &child_status, 0);
	if (!ASSERT_EQ(WEXITSTATUS(child_status), 0, "child_exit_value"))
		goto out;

	if (!ASSERT_OK(read_buildid("/bin/bash", &bid), "read_buildid"))
		goto out;

	ASSERT_EQ(skel->bss->build_id_size, strlen(bid)/2, "build_id_size");

	/* Convert bpf build id to string, so we can compare it later. */
	for (i = 0; i < skel->bss->build_id_size; i++) {
		sprintf(bpf_build_id + i*2, "%02x",
			(unsigned char) skel->bss->build_id[i]);
	}
	ASSERT_STREQ(bpf_build_id, bid, "build_id_data");

out:
	file_build_id__destroy(skel);
	free(bid);
}
