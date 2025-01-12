// SPDX-License-Identifier: GPL-2.0-only

#include <test_progs.h>
#include <bpf/btf.h>
#include <bpf/bpf.h>

#include "dynamic_tp.skel.h"

int dynamic_tp(const char *cmd)
{
	const char *kprobe_file = "/sys/kernel/debug/tracing/kprobe_events";
	ssize_t bytes_written;
	int fd, err;

	fd = open(kprobe_file, O_WRONLY | O_APPEND);
	if (!ASSERT_GE(fd, 0, "open kprobe_events"))
		return -1;

	bytes_written = write(fd, cmd, strlen(cmd));
	if (!ASSERT_GT(bytes_written, 0, "write kprobe_events")) {
		close(fd);
		return -1;
	}

	err = close(fd);
	if (!ASSERT_OK(err, "close kprobe_events"))
		return -1;
	return 0;
}

void test_dynamic_tp(void)
{
	struct dynamic_tp *skel;
	pid_t child_pid;
	int status, err;

	/* create a dynamic tracepoint */
	err = dynamic_tp("p:my_dynamic_tp kernel_clone");
	if (!ASSERT_OK(err, "create dynamic tp"))
		return;

	skel = dynamic_tp__open_and_load();
	if (!ASSERT_OK_PTR(skel, "load progs"))
		goto remove_tp;
	skel->bss->pid = getpid();
	err = dynamic_tp__attach(skel);
	if (!ASSERT_OK(err, "attach progs"))
		goto cleanup;

	/* trigger the dynamic tracepoint */
	child_pid = fork();
	if (!ASSERT_GT(child_pid, -1, "child_pid"))
		goto cleanup;
	if (child_pid == 0)
		_exit(0);
	waitpid(child_pid, &status, 0);

	ASSERT_EQ(skel->bss->result, 1, "result");

cleanup:
	dynamic_tp__destroy(skel);
remove_tp:
	dynamic_tp("-:my_dynamic_tp kernel_clone");
}
