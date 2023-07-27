// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <stdbool.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "trace_helpers.h"

static int map_fd, prog_fd;

static unsigned long long get_cgroup_inode(const char *path)
{
	unsigned long long inode;
	struct stat file_stat;
	int fd, ret;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return 0;

	ret = fstat(fd, &file_stat);
	if (ret < 0)
		return 0;

	inode = file_stat.st_ino;
	close(fd);
	return inode;
}

static int set_cgroup_oom_score(const char *cg_path, int score)
{
	unsigned long long ino = get_cgroup_inode(cg_path);

	if (!ino) {
		fprintf(stderr, "ERROR: get inode for %s failed\n", cg_path);
		return 1;
	}
	if (bpf_map_update_elem(map_fd, &ino, &score, BPF_ANY)) {
		fprintf(stderr, "ERROR: update map failed\n");
		return 1;
	}

	return 0;
}

/**
 * A simple sample of prefer select /root/blue/instance_1 as victim memcg
 * and protect /root/blue/instance_2
 *           root
 *       /         \
 *     user ...    blue
 *     /  \        /     \
 *     ..     instance_1  instance_2
 */

int main(int argc, char **argv)
{
	struct bpf_object *obj = NULL;
	struct bpf_program *prog;
	int target_fd = 0;
	unsigned int prog_cnt;

	obj = bpf_object__open_file("oom_kern.o", NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: opening BPF object file failed\n");
		obj = NULL;
		goto cleanup;
	}

	prog = bpf_object__next_program(obj, NULL);
	bpf_program__set_type(prog, BPF_PROG_TYPE_OOM_POLICY);
	/* load BPF program */
	if (bpf_object__load(obj)) {
		fprintf(stderr, "ERROR: loading BPF object file failed\n");
		goto cleanup;
	}

	map_fd = bpf_object__find_map_fd_by_name(obj, "sc_map");

	if (map_fd < 0) {
		fprintf(stderr, "ERROR: finding a map in obj file failed\n");
		goto cleanup;
	}

    /*
     *  In this sample, default score is 250 (see oom_kern.c).
     *  set high score for /blue and /blue/instance_1,
     *  so when global oom happened, /blue/instance_1 would
     *  be chosed as victim memcg
     */
	if (set_cgroup_oom_score("/sys/fs/cgroup/blue/", 500)) {
		fprintf(stderr, "ERROR: set score for /blue failed\n");
		goto cleanup;
	}
	if (set_cgroup_oom_score("/sys/fs/cgroup/blue/instance_1", 500)) {
		fprintf(stderr, "ERROR: set score for /blue/instance_2 failed\n");
		goto cleanup;
	}

	/* set low score to protect /blue/instance_2 */
	if (set_cgroup_oom_score("/sys/fs/cgroup/blue/instance_2", 100)) {
		fprintf(stderr, "ERROR: set score for /blue/instance_1 failed\n");
		goto cleanup;
	}

	prog_fd = bpf_program__fd(prog);

	/* Attach bpf program */
	if (bpf_prog_attach(prog_fd, target_fd, BPF_OOM_POLICY, 0)) {
		fprintf(stderr, "Failed to attach BPF_OOM_POLICY program");
		goto cleanup;
	}
	if (bpf_prog_query(target_fd, BPF_OOM_POLICY, 0, NULL, NULL, &prog_cnt)) {
		fprintf(stderr, "Failed to query attached programs\n");
		goto cleanup;
	}
	printf("prog_cnt: %d\n", prog_cnt);

cleanup:
	bpf_object__close(obj);
	return 0;
}
