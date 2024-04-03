// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2017 Facebook
 */

#include <test_progs.h>
#include <time.h>
#include "cgroup_helpers.h"
#include "dev_cgroup.skel.h"

#define TEST_CGROUP "/test-bpf-based-device-cgroup/"

#include <dirent.h>
#include <sys/types.h>

void print_all_dir(char *path) {
	DIR *directory;
	struct dirent *entry;

	directory = opendir(path);

	printf("directory %s:\n", path);
	if (directory == NULL) {
		perror("Error opening directory");
		return;
	}

	entry = readdir(directory);
	// Read directory entries
	while (entry != NULL) {
//		if (entry->d_type == DT_DIR)
		printf("%s\t", entry->d_name);
		entry = readdir(directory);
	}
	printf("\n");

	closedir(directory);
}

void serial_test_dev_cgroup(void)
{
	struct dev_cgroup *skel;
	int cgroup_fd, err;
	__u32 prog_cnt;

	skel = dev_cgroup__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		goto cleanup;

	cgroup_fd = cgroup_setup_and_join(TEST_CGROUP);
	if (!ASSERT_GT(cgroup_fd, 0, "cgroup_setup_and_join"))
		goto cleanup;

	err = bpf_prog_attach(bpf_program__fd(skel->progs.bpf_prog1), cgroup_fd,
			      BPF_CGROUP_DEVICE, 0);
	if (!ASSERT_EQ(err, 0, "bpf_attach"))
		goto cleanup;

	err = bpf_prog_query(cgroup_fd, BPF_CGROUP_DEVICE, 0, NULL, NULL, &prog_cnt);
	if (!ASSERT_EQ(err, 0, "bpf_query") || (!ASSERT_EQ(prog_cnt, 1, "bpf_query")))
		goto cleanup;

	/* All operations with /dev/zero and /dev/urandom are allowed,
	 * everything else is forbidden.
	 */
	ASSERT_EQ(system("rm -f /tmp/test_dev_cgroup_null"), 0, "rm");
	ASSERT_EQ(system("mknod --help"), 0, "mknod help");
	ASSERT_NEQ(system("mknod /tmp/test_dev_cgroup_null c 1 3"), 0, "mknod");
	ASSERT_EQ(system("rm -f /tmp/test_dev_cgroup_null"), 0, "rm");

	/* /dev/zero is whitelisted */
	ASSERT_EQ(system("rm -f /tmp/test_dev_cgroup_zero"), 0, "rm");
	ASSERT_EQ(system("rmfdfsffsd"), 0, "rmfdasfd");
	print_all_dir("/");
	print_all_dir("/tmp");
	print_all_dir("/usr/bin");
	errno = 0;
	int out = system("mknod /tmp/test_dev_cgroup_zero c 1 5");
	printf("\nout is %d expected 0 %d %m\n\n", out, errno);
	ASSERT_EQ(out, 0, "mknod"); //???
	print_all_dir("/tmp");
	ASSERT_EQ(system("rm -f /tmp/test_dev_cgroup_zero"), 0, "rm");

	ASSERT_EQ(system("dd if=/dev/urandom of=/dev/zero count=64"), 0, "dd");

	/* src is allowed, target is forbidden */
	ASSERT_NEQ(system("dd if=/dev/urandom of=/dev/full count=64"), 0, "dd");

	/* src is forbidden, target is allowed */
	ASSERT_NEQ(system("dd if=/dev/random of=/dev/zero count=64"), 0, "dd");

cleanup:
	cleanup_cgroup_environment();
	dev_cgroup__destroy(skel);
}
