// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/stat.h>
#include <test_progs.h>
#include <bpf/btf.h>
#include <bpf/bpf.h>

#include "cgroup_helpers.h"
#include "oom_policy.skel.h"

static int map_fd;
static int cg_nr;
struct {
	const char *path;
	int fd;
	unsigned long long id;
} cgs[] = {
	{ "/cg1" },
	{ "/cg2" },
};


static struct oom_policy *open_load_oom_policy_skel(void)
{
	struct oom_policy *skel;
	int err;

	skel = oom_policy__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return NULL;

	err = oom_policy__load(skel);
	if (!ASSERT_OK(err, "skel_load"))
		goto cleanup;

	return skel;

cleanup:
	oom_policy__destroy(skel);
	return NULL;
}

static void run_memory_consume(unsigned long long consume_size, int idx)
{
	char *buf;

	join_parent_cgroup(cgs[idx].path);
	buf = malloc(consume_size);
	memset(buf, 0, consume_size);
	sleep(2);
	exit(0);
}

static int set_cgroup_prio(unsigned long long cg_id, int prio)
{
	int err;

	err = bpf_map_update_elem(map_fd, &cg_id, &prio, BPF_ANY);
	ASSERT_EQ(err, 0, "update_map");
	return err;
}

static int prepare_cgroup_environment(void)
{
	int err;

	err = setup_cgroup_environment();
	if (err)
		goto clean_cg_env;
	for (int i = 0; i < cg_nr; i++) {
		err = cgs[i].fd = create_and_get_cgroup(cgs[i].path);
		if (!ASSERT_GE(cgs[i].fd, 0, "cg_create"))
			goto clean_cg_env;
		cgs[i].id = get_cgroup_id(cgs[i].path);
	}
	return 0;
clean_cg_env:
	cleanup_cgroup_environment();
	return err;
}

void test_oom_policy(void)
{
	struct oom_policy *skel;
	struct bpf_link *link;
	int err;
	int victim_pid;
	unsigned long long victim_cg_id;

	link = NULL;
	cg_nr = ARRAY_SIZE(cgs);

	skel = open_load_oom_policy_skel();
	err = oom_policy__attach(skel);
	if (!ASSERT_OK(err, "oom_policy__attach"))
		goto cleanup;

	map_fd = bpf_object__find_map_fd_by_name(skel->obj, "cg_map");
	if (!ASSERT_GE(map_fd, 0, "find map"))
		goto cleanup;

	err = prepare_cgroup_environment();
	if (!ASSERT_EQ(err, 0, "prepare cgroup env"))
		goto cleanup;

	write_cgroup_file("/", "memory.max", "10M");

	/*
	 * Set higher priority to cg2 and lower to cg1, so we would select
	 * task under cg1 as victim.(see oom_policy.c)
	 */
	set_cgroup_prio(cgs[0].id, 10);
	set_cgroup_prio(cgs[1].id, 50);

	victim_cg_id = cgs[0].id;
	victim_pid = fork();

	if (victim_pid == 0)
		run_memory_consume(1024 * 1024 * 4, 0);

	if (fork() == 0)
		run_memory_consume(1024 * 1024 * 8, 1);

	while (wait(NULL) > 0)
		;

	ASSERT_EQ(skel->bss->victim_pid, victim_pid, "victim_pid");
	ASSERT_EQ(skel->bss->victim_cg_id, victim_cg_id, "victim_cgid");

cleanup:
	bpf_link__destroy(link);
	oom_policy__destroy(skel);
	cleanup_cgroup_environment();
}
