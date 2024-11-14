// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */

#define _GNU_SOURCE
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/fanotify.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <test_progs.h>

#include "fan_fp.skel.h"

#define TEST_FS "/tmp/"
#define TEST_DIR "/tmp/fanotify_test/"

static int create_test_subtree(void)
{
	int err;

	err = mkdir(TEST_DIR, 0777);
	if (err && errno != EEXIST)
		return err;

	return open(TEST_DIR, O_RDONLY);
}

static int create_fanotify_fd(void)
{
	int fanotify_fd, err;

	fanotify_fd = fanotify_init(FAN_CLASS_NOTIF | FAN_REPORT_NAME | FAN_REPORT_DIR_FID,
				    O_RDONLY);

	if (!ASSERT_OK_FD(fanotify_fd, "fanotify_init"))
		return -1;

	err = fanotify_mark(fanotify_fd, FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
			    FAN_CREATE | FAN_OPEN | FAN_ONDIR | FAN_EVENT_ON_CHILD,
			    AT_FDCWD, TEST_FS);
	if (!ASSERT_OK(err, "fanotify_mark")) {
		close(fanotify_fd);
		return -1;
	}

	return fanotify_fd;
}

static int attach_global_fastpath(int fanotify_fd)
{
	struct fanotify_fastpath_args args = {
		.name = "_tmp_test_sub_tree",
		.version = 1,
		.flags = 0,
	};

	if (ioctl(fanotify_fd, FAN_IOC_ADD_FP, &args))
		return -1;

	return 0;
}

#define EVENT_BUFFER_SIZE 4096
struct file_access_result {
	char name_prefix[16];
	bool accessed;
} access_results[3] = {
	{"aa", false},
	{"bb", false},
	{"cc", false},
};

static void update_access_results(char *name)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(access_results); i++) {
		if (strcmp(name, access_results[i].name_prefix) == 0)
			access_results[i].accessed = true;
	}
}

static void parse_event(char *buffer, int len)
{
	struct fanotify_event_metadata *event =
		(struct fanotify_event_metadata *) buffer;
	struct fanotify_event_info_header *info;
	struct fanotify_event_info_fid *fid;
	struct file_handle *handle;
	char *name;
	int off;

	for (; FAN_EVENT_OK(event, len); event = FAN_EVENT_NEXT(event, len)) {
		for (off = sizeof(*event) ; off < event->event_len;
		     off += info->len) {
			info = (struct fanotify_event_info_header *)
				((char *) event + off);
			switch (info->info_type) {
			case FAN_EVENT_INFO_TYPE_DFID_NAME:
				fid = (struct fanotify_event_info_fid *) info;
				handle = (struct file_handle *)&fid->handle;
				name = (char *)handle + sizeof(*handle) + handle->handle_bytes;
				update_access_results(name);
				break;
			default:
				break;
			}
		}
	}
}

static void touch_file(const char *path)
{
	int fd;

	fd = open(path, O_WRONLY|O_CREAT|O_NOCTTY|O_NONBLOCK, 0666);
	if (!ASSERT_OK_FD(fd, "open"))
		goto cleanup;
	close(fd);
cleanup:
	unlink(path);
}

static void generate_and_test_event(int fanotify_fd, struct fan_fp *skel)
{
	char buffer[EVENT_BUFFER_SIZE];
	int len, err, fd;

	/* Open the dir, so initialize_subdir_root can work */
	fd = open(TEST_DIR, O_RDONLY);
	close(fd);

	if (!ASSERT_EQ(skel->bss->initialized, true, "initialized"))
		goto cleanup;

	/* access /tmp/fanotify_test/aa, this will generate event */
	touch_file(TEST_DIR "aa");

	/* create /tmp/fanotify_test/subdir, this will get tag from the
	 * parent directory (added in the bpf program on fsnotify_mkdir)
	 */
	err = mkdir(TEST_DIR "subdir", 0777);
	ASSERT_OK(err, "mkdir");

	/* access /tmp/fanotify_test/subdir/bb, this will generate event */
	touch_file(TEST_DIR "subdir/bb");

	/* access /tmp/cc, this will NOT generate event, as the BPF
	 * fastpath filtered this event out. (Because /tmp doesn't have
	 * the tag.)
	 */
	touch_file(TEST_FS "cc");

	/* read and parse the events */
	len = read(fanotify_fd, buffer, EVENT_BUFFER_SIZE);
	if (!ASSERT_GE(len, 0, "read event"))
		goto cleanup;
	parse_event(buffer, len);

	/* verify we generated events for aa and bb, but filtered out the
	 * event for cc.
	 */
	ASSERT_TRUE(access_results[0].accessed, "access aa");
	ASSERT_TRUE(access_results[1].accessed, "access bb");
	ASSERT_FALSE(access_results[2].accessed, "access cc");

	/* Each touch_file() generates two events: FAN_CREATE then
	 * FAN_OPEN. The second event will hit cache.
	 * open(TEST_DIR) also hit cache, as we updated it cache for
	 * TEST_DIR from userspace.
	 * Therefore, we expect 4 cache hits: aa, bb, cc, and TEST_DIR.
	 */
	ASSERT_EQ(skel->bss->cache_hit, 4, "cache_hit");

cleanup:
	rmdir(TEST_DIR "subdir");
	rmdir(TEST_DIR);
}

/* This test shows a simplified logic that monitors a subtree. This is
 * simplified as it doesn't handle all the scenarios, such as:
 *
 *  1) moving a subsubtree into/outof the being monitoring subtree;
 *  2) mount point inside the being monitored subtree
 *
 * Therefore, this is not to show a way to reliably monitor a subtree.
 * Instead, this is to test the functionalities of bpf based fastpath.
 *
 * Overview of the logic:
 * 1. fanotify is created for the whole file system (/tmp);
 * 2. A bpf map (inode_storage_map) is used to tag directories to
 *    monitor (starting from /tmp/fanotify_test);
 * 3. On fsnotify_mkdir, thee tag is propagated to newly created sub
 *    directories (/tmp/fanotify_test/subdir);
 * 4. The bpf fastpath checks whether the event happens in a directory
 *    with the tag. If yes, the event is sent to user space; otherwise,
 *    the event is dropped.
 */
static void test_monitor_subtree(void)
{
	struct bpf_link *link;
	struct fan_fp *skel;
	int test_root_fd;
	int zero = 0;
	int err, fanotify_fd;
	struct stat st;

	test_root_fd = create_test_subtree();

	if (!ASSERT_OK_FD(test_root_fd, "create_test_subtree"))
		return;

	err = fstat(test_root_fd, &st);
	if (!ASSERT_OK(err, "fstat test_root_fd"))
		goto close_test_root_fd;

	skel = fan_fp__open_and_load();

	if (!ASSERT_OK_PTR(skel, "fan_fp__open_and_load"))
		goto close_test_root_fd;

	skel->bss->root_ino = st.st_ino;

	/* Add tag to /tmp/fanotify_test/ */
	err = bpf_map_update_elem(bpf_map__fd(skel->maps.inode_storage_map),
				  &test_root_fd, &zero, BPF_ANY);
	if (!ASSERT_OK(err, "bpf_map_update_elem"))
		goto destroy_skel;
	link = bpf_map__attach_struct_ops(skel->maps.bpf_fanotify_fastpath_ops);
	if (!ASSERT_OK_PTR(link, "bpf_map__attach_struct_ops"))
		goto destroy_skel;

	fanotify_fd = create_fanotify_fd();
	if (!ASSERT_OK_FD(fanotify_fd, "create_fanotify_fd"))
		goto destroy_link;

	err = attach_global_fastpath(fanotify_fd);
	if (!ASSERT_OK(err, "attach_global_fastpath"))
		goto close_fanotify_fd;

	generate_and_test_event(fanotify_fd, skel);

close_fanotify_fd:
	close(fanotify_fd);

destroy_link:
	bpf_link__destroy(link);
destroy_skel:
	fan_fp__destroy(skel);

close_test_root_fd:
	close(test_root_fd);
	rmdir(TEST_DIR);
}

void test_bpf_fanotify_fastpath(void)
{
	if (test__start_subtest("subtree"))
		test_monitor_subtree();
}
