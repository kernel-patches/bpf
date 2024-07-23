// SPDX-License-Identifier: GPL-2.0

#include <sys/stat.h>
#include <sys/sysmacros.h>
#include "test_progs.h"
#include "cgroup_helpers.h"
#include "dev_cgroup.skel.h"

#define TEST_CGROUP "/test-bpf-based-device-cgroup/"
#define TEST_BUFFER_SIZE 64

static void test_mknod(const char *path, mode_t mode, int dev_major,
		       int dev_minor, int expected_ret)
{
	int ret;

	unlink(path);
	ret = mknod(path, mode, makedev(dev_major, dev_minor));
	ASSERT_EQ(ret, expected_ret, "mknod");
	unlink(path);
}

static void test_read(const char *path, char *buf, int buf_size, int expected_ret)
{
	int ret, fd;

	fd = open(path, O_RDONLY);

	/* A bare open on unauthorized device should fail */
	if (expected_ret < 0 ) {
		ASSERT_EQ(fd, expected_ret, "open file for read");
		if (fd >= 0)
			close(fd);
		return;
	}

	if (!ASSERT_OK_FD(fd, "open file for read"))
		return;

	ret = read(fd, buf, buf_size);
	ASSERT_EQ(ret, expected_ret, "read");

	close(fd);
}

static void test_write(const char *path, char *buf, int buf_size, int expected_ret)
{
	int ret, fd;

	fd = open(path, O_WRONLY);

	/* A bare open on unauthorized device should fail */
	if (expected_ret < 0) {
		ASSERT_EQ(fd, expected_ret, "open file for write");
		if (fd >= 0)
			close(fd);
		return;
	}

	if (!ASSERT_OK_FD(fd, "open file for write"))
		return;

	ret = write(fd, buf, buf_size);
	ASSERT_EQ(ret, expected_ret, "write");

	close(fd);
}

void test_cgroup_dev(void)
{
	char buf[TEST_BUFFER_SIZE] = "some random test data";
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
		test_mknod("/dev/test_dev_cgroup_zero", S_IFCHR, 1, 5, -EPERM);

	if (test__start_subtest("allow-mknod"))
		test_mknod("/dev/test_dev_cgroup_null", S_IFCHR, 1, 3, 0);

	if (test__start_subtest("allow-read"))
		test_read("/dev/urandom", buf, TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);

	if (test__start_subtest("allow-write"))
		test_write("/dev/null", buf, TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);

	if (test__start_subtest("deny-read"))
		test_read("/dev/random", buf, TEST_BUFFER_SIZE, -EPERM);

	if (test__start_subtest("deny-write"))
		test_write("/dev/zero", buf, TEST_BUFFER_SIZE, -EPERM);

cleanup_progs:
	dev_cgroup__destroy(skel);
cleanup_cgroup:
	cleanup_cgroup_environment();
}
