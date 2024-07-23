// SPDX-License-Identifier: GPL-2.0

#include <sys/stat.h>
#include <sys/sysmacros.h>
#include "test_progs.h"
#include "cgroup_helpers.h"
#include "dev_cgroup.skel.h"

#define TEST_CGROUP "/test-bpf-based-device-cgroup/"
#define TEST_BUFFER_SIZE 64

static void test_mknod(const char *path, mode_t mode, int dev_major,
		       int dev_minor, int should_fail)
{
	int ret;

	unlink(path);
	ret = mknod(path, mode, makedev(dev_major, dev_minor));
	if (should_fail)
		ASSERT_ERR(ret, "mknod");
	else
		ASSERT_OK(ret, "mknod");
	unlink(path);
}

static void test_read(const char *path, int should_fail)
{
	char buf[TEST_BUFFER_SIZE];
	int ret, fd;

	fd = open(path, O_RDONLY);

	/* A bare open on unauthorized device should fail */
	if (should_fail) {
		ASSERT_ERR(fd, "open file for read");
		if (fd)
			close(fd);
		return;
	}

	if (!ASSERT_OK_FD(fd, "open file for read"))
		return;

	ret = read(fd, buf, TEST_BUFFER_SIZE);
	if (should_fail)
		ASSERT_ERR(ret, "read");
	else
		ASSERT_EQ(ret, TEST_BUFFER_SIZE, "read");

	close(fd);
}

static void test_write(const char *path, int should_fail)
{
	char buf[] = "some random test data";
	int ret, fd;

	fd = open(path, O_WRONLY);

	/* A bare open on unauthorized device should fail */
	if (should_fail) {
		ASSERT_ERR(fd, "open file for write");
		if (fd)
			close(fd);
		return;
	}

	if (!ASSERT_OK_FD(fd, "open file for write"))
		return;

	ret = write(fd, buf, sizeof(buf));
	if (should_fail)
		ASSERT_ERR(ret, "write");
	else
		ASSERT_EQ(ret, sizeof(buf), "write");

	close(fd);
}

void test_cgroup_dev(void)
{
	struct dev_cgroup *skel;
	int cgroup_fd;

	cgroup_fd = cgroup_setup_and_join(TEST_CGROUP);
	if (!ASSERT_OK_FD(cgroup_fd, "cgroup switch"))
		return;

	skel = dev_cgroup__open_and_load();
	if (!ASSERT_OK_PTR(skel, "load program"))
		goto cleanup_cgroup;

	if (!ASSERT_OK(bpf_prog_attach(bpf_program__fd(skel->progs.bpf_prog1),
				       cgroup_fd, BPF_CGROUP_DEVICE, 0),
		       "attach_program"))
		goto cleanup_progs;

	if (test__start_subtest("deny-mknod"))
		test_mknod("/tmp/test_dev_cgroup_zero", S_IFCHR, 1, 5, 1);

	if (test__start_subtest("allow-mknod"))
		test_mknod("/tmp/test_dev_cgroup_null", S_IFCHR, 1, 3, 0);

	if (test__start_subtest("allow-read"))
		test_read("/dev/urandom", 0);

	if (test__start_subtest("allow-write"))
		test_write("/dev/null", 0);

	if (test__start_subtest("deny-read"))
		test_read("/dev/random", 1);

	if (test__start_subtest("deny-write"))
		test_write("/dev/zero", 1);

cleanup_progs:
	dev_cgroup__destroy(skel);
cleanup_cgroup:
	cleanup_cgroup_environment();
}
