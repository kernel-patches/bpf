// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Google */
#define _GNU_SOURCE
#include <sys/stat.h>	/* mkdir */
#include <fcntl.h>	/* name_to_handle_at */
#include <stdlib.h>
#include <test_progs.h>
#include "cgroup_monitor.skel.h"
#include "cgroup_sched_lat.skel.h"

static char mkdir_prog_path[64];
static char rmdir_prog_path[64];
static char dump_prog_path[64];

/* Get cgroup id from a full path to cgroup */
static int get_cgroup_id(const char *cgroup)
{
	int mount_id = 0;
	struct {
		struct file_handle fh;
		__u64 cgid;
	} fh = {};

	fh.fh.handle_bytes = sizeof(fh.cgid);
	if (name_to_handle_at(AT_FDCWD, cgroup, &fh.fh, &mount_id, 0))
		return -1;

	return fh.cgid;
}

static void spin_on_cpu(int seconds)
{
	time_t start, now;

	start = time(NULL);
	do {
		now = time(NULL);
	} while (now - start < seconds);
}

static void do_work(const char *cgroup)
{
	int i, cpu = 0, pid;
	char cmd[128];

	/* make cgroup threaded */
	snprintf(cmd, 128, "echo threaded > %s/cgroup.type", cgroup);
	system(cmd);

	/* try to enable cpu controller. this may fail if cpu controller is not
	 * available in cgroup.controllers or there is a cgroup v1 already
	 * mounted in the system.
	 */
	snprintf(cmd, 128, "echo \"+cpu\" > %s/cgroup.subtree_control", cgroup);
	system(cmd);

	/* launch two children, both running in child cgroup */
	for (i = 0; i < 2; ++i) {
		pid = fork();
		if (pid == 0) {
			/* attach to cgroup */
			snprintf(cmd, 128, "echo %d > %s/cgroup.procs", getpid(), cgroup);
			system(cmd);

			/* pin process to target cpu */
			snprintf(cmd, 128, "taskset -pc %d %d", cpu, getpid());
			system(cmd);

			spin_on_cpu(3); /* spin on cpu for 3 seconds */
			exit(0);
		}
	}

	/* pin parent process to target cpu */
	snprintf(cmd, 128, "taskset -pc %d %d", cpu, getpid());
	system(cmd);

	spin_on_cpu(3); /* spin on cpu for 3 seconds */
	wait(NULL);
}

/* Check reading cgroup stats from auto pinned objects
 * @root: root directory in bpffs set up for this test
 * @cgroup: cgroup path
 */
static void check_cgroup_stats(const char *root, const char *cgroup)
{
	unsigned long queue_self, queue_other;
	char buf[64], path[64];
	int id, cgroup_id;
	FILE *file;

	id = get_cgroup_id(cgroup);
	if (!ASSERT_GE(id, 0, "get_cgroup_id"))
		return;

	snprintf(path, sizeof(path), "%s/%d/stats", root, id);
	file = fopen(path, "r");
	if (!ASSERT_OK_PTR(file, "open"))
		return;

	ASSERT_OK_PTR(fgets(buf, sizeof(buf), file), "cat");
	ASSERT_EQ(sscanf(buf, "cgroup_id: %8d", &cgroup_id), 1, "output");
	ASSERT_EQ(id, cgroup_id, "cgroup_id");

	ASSERT_OK_PTR(fgets(buf, sizeof(buf), file), "cat");
	ASSERT_EQ(sscanf(buf, "queue_self: %8lu", &queue_self), 1, "output");

	ASSERT_OK_PTR(fgets(buf, sizeof(buf), file), "cat");
	ASSERT_EQ(sscanf(buf, "queue_other: %8lu", &queue_other), 1, "output");
	fclose(file);
}

/* Set up bpf progs for monitoring cgroup activities. */
static void setup_cgroup_monitor(const char *root)
{
	struct cgroup_monitor *skel = NULL;

	skel = cgroup_monitor__open_and_load();
	if (!ASSERT_OK_PTR(skel, "cgroup_monitor_skel_load"))
		return;

	cgroup_monitor__attach(skel);

	snprintf(skel->bss->root, sizeof(skel->bss->root), "%s", root);

	snprintf(mkdir_prog_path, 64, "%s/mkdir_prog", root);
	bpf_obj_pin(bpf_link__fd(skel->links.mkdir_prog), mkdir_prog_path);

	snprintf(rmdir_prog_path, 64, "%s/rmdir_prog", root);
	bpf_obj_pin(bpf_link__fd(skel->links.rmdir_prog), rmdir_prog_path);

	cgroup_monitor__destroy(skel);
}

void test_cgroup_stats(void)
{
	char bpf_tmpl[] = "/sys/fs/bpf/XXXXXX";
	char cgrp_tmpl[] = "/sys/fs/cgroup/XXXXXX";
	struct cgroup_sched_lat *skel = NULL;
	char *root, *cgroup;

	/* prepare test directories */
	system("mount -t cgroup2 none /sys/fs/cgroup");
	system("mount -t bpf bpffs /sys/fs/bpf");
	root = mkdtemp(bpf_tmpl);
	chmod(root, 0777);

	/* set up progs for monitoring cgroup events */
	setup_cgroup_monitor(root);

	/* set up progs for profiling cgroup stats */
	skel = cgroup_sched_lat__open_and_load();
	if (!ASSERT_OK_PTR(skel, "cgroup_sched_lat_skel_load"))
		goto cleanup_root;

	snprintf(dump_prog_path, 64, "%s/prog", root);
	bpf_obj_pin(bpf_program__fd(skel->progs.dump_cgroup), dump_prog_path);
	chmod(dump_prog_path, 0644);

	cgroup_sched_lat__attach(skel);

	/* thanks to cgroup monitoring progs, a directory corresponding to the
	 * cgroup is created in bpffs.
	 */
	cgroup = mkdtemp(cgrp_tmpl);

	/* collect some cgroup-level stats and check reading them from bpffs */
	do_work(cgroup);
	check_cgroup_stats(root, cgroup);

	/* thanks to cgroup monitoring progs, removing cgroups also removes
	 * the created directory in bpffs.
	 */
	rmdir(cgroup);

	/* clean up cgroup monitoring progs */
	cgroup_sched_lat__detach(skel);
	cgroup_sched_lat__destroy(skel);
	unlink(dump_prog_path);
cleanup_root:
	/* remove test directories in bpffs */
	unlink(mkdir_prog_path);
	unlink(rmdir_prog_path);
	rmdir(root);
	return;
}
