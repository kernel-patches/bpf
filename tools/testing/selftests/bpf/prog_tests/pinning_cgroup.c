// SPDX-License-Identifier: GPL-2.0

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <test_progs.h>
#include <time.h>
#include <unistd.h>
#include "bpf_iter_cgroup_view.skel.h"

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

	/* try to enable cpu controller. this may fail if there cpu controller
	 * is not available in cgroup.controllers or there is a cgroup v1 already
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

	/* pin process to target cpu */
	snprintf(cmd, 128, "taskset -pc %d %d", cpu, getpid());
	system(cmd);

	spin_on_cpu(3); /* spin on cpu for 3 seconds */
	wait(NULL);
}

static void check_pinning(const char *rootpath)
{
	const char *child_cgroup = "/sys/fs/cgroup/child";
	struct bpf_iter_cgroup_view *skel;
	struct bpf_link *link;
	struct stat statbuf = {};
	FILE *file;
	unsigned long queue_self, queue_other;
	int cgroup_id, link_fd;
	char path[64];
	char buf[64];

	skel = bpf_iter_cgroup_view__open_and_load();
	if (!ASSERT_OK_PTR(skel, "bpf_iter_cgroup_view__open_and_load"))
		return;

	/* pin path at parent dir. */
	link = bpf_program__attach_iter(skel->progs.dump_cgroup_lat, NULL);
	link_fd = bpf_link__fd(link);

	/* test initial pinning */
	snprintf(path, 64, "%s/obj", rootpath);
	ASSERT_OK(bpf_obj_pin(link_fd, path), "bpf_obj_pin");
	ASSERT_OK(stat(path, &statbuf), "pinned_object_exists");

	/* test mkdir */
	mkdir(child_cgroup, 0755);
	snprintf(path, 64, "%s/child", rootpath);
	ASSERT_OK(mkdir(path, 0755), "mkdir");

	/* test that new dir has been pre-populated with pinned objects */
	snprintf(path, 64, "%s/child/obj", rootpath);
	ASSERT_OK(stat(path, &statbuf), "populate");

	bpf_iter_cgroup_view__attach(skel);
	do_work(child_cgroup);
	bpf_iter_cgroup_view__detach(skel);

	/* test cat inherited objects */
	file = fopen(path, "r");
	if (ASSERT_OK_PTR(file, "open")) {
		ASSERT_OK_PTR(fgets(buf, sizeof(buf), file), "cat");
		ASSERT_EQ(sscanf(buf, "cgroup_id: %8d", &cgroup_id), 1, "output");

		ASSERT_OK_PTR(fgets(buf, sizeof(buf), file), "cat");
		ASSERT_EQ(sscanf(buf, "queue_self: %8lu", &queue_self), 1, "output");

		ASSERT_OK_PTR(fgets(buf, sizeof(buf), file), "cat");
		ASSERT_EQ(sscanf(buf, "queue_other: %8lu", &queue_other), 1, "output");

		fclose(file);
	}

	/* test rmdir */
	snprintf(path, 64, "%s/child", rootpath);
	ASSERT_OK(rmdir(path), "rmdir");

	/* unpin object */
	snprintf(path, 64, "%s/obj", rootpath);
	ASSERT_OK(unlink(path), "unlink");

	bpf_link__destroy(link);
	bpf_iter_cgroup_view__destroy(skel);
}

void test_pinning_cgroup(void)
{
	char tmpl[] = "/sys/fs/bpf/pinning_test_XXXXXX";
	char *rootpath;

	system("mount -t cgroup2 none /sys/fs/cgroup");
	system("mount -t bpf bpffs /sys/fs/bpf");

	rootpath = mkdtemp(tmpl);
	chmod(rootpath, 0755);

	/* check pinning map, prog and link in kernfs */
	if (test__start_subtest("pinning"))
		check_pinning(rootpath);

	rmdir(rootpath);
}
