// SPDX-License-Identifier: GPL-2.0
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <unistd.h>
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <linux/sched.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

static int create_bpf_map(const char *name)
{
	static struct bpf_map_create_opts map_opts = {
		.sz = sizeof(map_opts),
	};
	unsigned int value;
	unsigned int key;
	int map_fd;

	map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, name, sizeof(key),
							sizeof(value), 1, &map_opts);
	if (map_fd < 0)
		fprintf(stderr, "%s - Failed to create map\n", strerror(errno));
	return map_fd;
}


int main(int argc, char *argv[])
{
	struct bpf_map_info info = {};
	__u32 info_len = sizeof(info);
	struct clone_args args = {
		.flags = 0x400000000ULL,	/* CLONE_NEWBPF */
		.exit_signal = SIGCHLD,
	};
	int map_fd, child_map_fd;
	pid_t pid;

	/* Create a map in init bpf namespace. */
	map_fd = create_bpf_map("map_in_init");
	if (map_fd < 0)
		exit(EXIT_FAILURE);
	pid = syscall(__NR_clone3, &args, sizeof(struct clone_args));
	if (pid < 0) {
		fprintf(stderr, "%s - Failed to create new process\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (pid == 0) {
		struct bpf_map_info info = {};

		/* In a new bpf namespace, it is the first map. */
		child_map_fd = create_bpf_map("map_in_bpfns");
		if (child_map_fd < 0)
			exit(EXIT_FAILURE);
		bpf_obj_get_info_by_fd(child_map_fd, &info, &info_len);
		assert(info.id == 1);
		exit(EXIT_SUCCESS);
	}

	if (waitpid(pid, NULL, 0) != pid) {
		fprintf(stderr, "Failed to wait on child process\n");
		exit(EXIT_FAILURE);
	}

	return 0;
}
