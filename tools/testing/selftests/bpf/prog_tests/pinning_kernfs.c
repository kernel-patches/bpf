// SPDX-License-Identifier: GPL-2.0

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <test_progs.h>
#include <time.h>
#include <unistd.h>
#include "pinning_kernfs.skel.h"

/* remove pinned object from kernfs */
static void do_unpin(const char *kernfs_path, const char *msg)
{
	struct stat statbuf = {};
	const char cmd[] = "rm";
	int fd;

	fd = open(kernfs_path, O_WRONLY);
	if (fd < 0)
		return;
	ASSERT_GE(write(fd, cmd, sizeof(cmd)), 0, "fail_unpin_cgroup_entry");
	close(fd);

	ASSERT_ERR(stat(kernfs_path, &statbuf), msg);
}

static void do_pin(int fd, const char *pinpath)
{
	struct stat statbuf = {};

	if (!ASSERT_OK(bpf_obj_pin(fd, pinpath), "bpf_obj_pin"))
		return;

	ASSERT_OK(stat(pinpath, &statbuf), "stat");
}

static void check_pinning(const char *bpffs_rootpath,
			  const char *kernfs_rootpath)
{
	const char msg[] = "xxx";
	char buf[8];
	struct pinning_kernfs *skel;
	struct bpf_link *link;
	int prog_fd, map_fd, link_fd;
	char bpffs_path[64];
	char kernfs_path[64];
	struct stat statbuf = {};
	int err, fd;

	skel = pinning_kernfs__open_and_load();
	if (!ASSERT_OK_PTR(skel, "pinning_kernfs__open_and_load"))
		return;

	snprintf(kernfs_path, 64, "%s/bpf_obj", kernfs_rootpath);
	snprintf(bpffs_path, 64, "%s/bpf_obj", bpffs_rootpath);

	prog_fd = bpf_program__fd(skel->progs.wait_show);

	/* test 1:
	 *
	 *  - expose object in kernfs without pinning in bpffs in the first place.
	 */
	ASSERT_ERR(bpf_obj_pin(prog_fd, kernfs_path), "pin_kernfs_first");

	/* test 2:
	 *
	 *  - expose bpf prog in kernfs.
	 *  - read/write the newly creaded kernfs entry.
	 */
	do_pin(prog_fd, bpffs_path);
	do_pin(prog_fd, kernfs_path);
	fd = open(kernfs_path, O_RDWR);
	err = read(fd, buf, sizeof(buf));
	if (!ASSERT_EQ(err, -1, "unexpected_successful_read"))
		goto out;

	err = write(fd, msg, sizeof(msg));
	if (!ASSERT_EQ(err, -1, "unexpected_successful_write"))
		goto out;

	close(fd);
	do_unpin(kernfs_path, "kernfs_unpin_prog");
	ASSERT_OK(unlink(bpffs_path), "bpffs_unlink_prog");

	/* test 3:
	 *
	 *  - expose bpf map in kernfs.
	 *  - read/write the newly created kernfs entry.
	 */
	map_fd = bpf_map__fd(skel->maps.wait_map);
	do_pin(map_fd, bpffs_path);
	do_pin(map_fd, kernfs_path);
	fd = open(kernfs_path, O_RDWR);
	err = read(fd, buf, sizeof(buf));
	if (!ASSERT_EQ(err, -1, "unexpected_successful_read"))
		goto out;

	err = write(fd, msg, sizeof(msg));
	if (!ASSERT_EQ(err, -1, "unexpected_successful_write"))
		goto out;

	close(fd);
	do_unpin(kernfs_path, "kernfs_unpin_map");
	ASSERT_OK(unlink(bpffs_path), "bpffs_unlink_map");

	/* test 4:
	 *
	 *  - expose bpf link in kernfs.
	 *  - read/write the newly created kernfs entry.
	 *  - removing bpffs entry also removes kernfs entries.
	 */
	link = bpf_program__attach(skel->progs.wait_record);
	link_fd = bpf_link__fd(link);
	do_pin(link_fd, bpffs_path);
	do_pin(link_fd, kernfs_path);
	fd = open(kernfs_path, O_RDWR);
	err = read(fd, buf, sizeof(buf));
	if (!ASSERT_EQ(err, -1, "unexpected_successful_read"))
		goto destroy_link;

	err = write(fd, msg, sizeof(msg));
	if (!ASSERT_EQ(err, -1, "unexpected_successful_write"))
		goto destroy_link;

	ASSERT_OK(unlink(bpffs_path), "bpffs_unlink_link");
	ASSERT_ERR(stat(kernfs_path, &statbuf), "unpin_bpffs_first");

	/* cleanup */
destroy_link:
	bpf_link__destroy(link);
out:
	close(fd);
	pinning_kernfs__destroy(skel);
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
	int cpu = 0, pid;
	char cmd[128];

	/* make cgroup threaded */
	snprintf(cmd, 128, "echo threaded > %s/cgroup.type", cgroup);
	system(cmd);

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

	/* pin process to target cpu */
	snprintf(cmd, 128, "taskset -pc %d %d", cpu, getpid());
	system(cmd);

	spin_on_cpu(3); /* spin on cpu for 3 seconds */
	wait(NULL);
}

void read_from_file(const char *path)
{
	int id = 0, lat;
	char buf[64];
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return;
	ASSERT_GE(read(fd, buf, sizeof(buf)), 0, "fail_read_cgroup_entry");
	ASSERT_EQ(sscanf(buf, "%d %d", &id, &lat), 2, "unexpected_seq_show_output");
	close(fd);
}

static void check_cgroup_seq_show(const char *bpffs_dir,
				  const char *cgroup_dir)
{
	struct pinning_kernfs *skel;
	char bpffs_path[64];
	char cgroup_path[64];
	int fd;

	skel = pinning_kernfs__open_and_load();
	if (!ASSERT_OK_PTR(skel, "pinning_kernfs__open_and_load"))
		return;

	pinning_kernfs__attach(skel);

	snprintf(bpffs_path, 64, "%s/bpf_obj", bpffs_dir);
	snprintf(cgroup_path, 64, "%s/bpf_obj", cgroup_dir);

	/* generate wait events for the cgroup */
	do_work(cgroup_dir);

	/* expose wait_show prog to cgroupfs */
	fd = bpf_link__fd(skel->links.wait_show);
	ASSERT_OK(bpf_obj_pin(fd, bpffs_path), "pin_bpffs");
	ASSERT_OK(bpf_obj_pin(fd, cgroup_path), "pin_cgroupfs");

	/* read from cgroupfs and check results */
	read_from_file(cgroup_path);

	/* cleanup */
	do_unpin(cgroup_path, "cgroup_unpin_seq_show");
	ASSERT_OK(unlink(bpffs_path), "bpffs_unlink_seq_show");

	pinning_kernfs__destroy(skel);
}

void test_pinning_kernfs(void)
{
	char kernfs_tmpl[] = "/sys/fs/cgroup/bpf_pinning_test_XXXXXX";
	char bpffs_tmpl[] = "/sys/fs/bpf/pinning_test_XXXXXX";
	char *kernfs_rootpath, *bpffs_rootpath;

	kernfs_rootpath = mkdtemp(kernfs_tmpl);
	bpffs_rootpath = mkdtemp(bpffs_tmpl);

	/* check pinning map, prog and link in kernfs */
	if (test__start_subtest("pinning"))
		check_pinning(bpffs_rootpath, kernfs_rootpath);

	/* check cgroup seq_show implemented using bpf */
	if (test__start_subtest("cgroup_seq_show"))
		check_cgroup_seq_show(bpffs_rootpath, kernfs_rootpath);

	rmdir(kernfs_rootpath);
	rmdir(bpffs_rootpath);
}
