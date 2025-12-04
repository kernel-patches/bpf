// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Google LLC */

#include <test_progs.h>
#include <bpf/libbpf.h>
#include "wakeup_source_iter.skel.h"

#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


/* Sleep for 10ms to ensure active time is > 0 after converting ns to ms*/
#define TEST_SLEEP_US 10000
#define TEST_SLEEP_MS (TEST_SLEEP_US / 1000)
#define WAKEUP_SOURCE_NAME_LEN 32

static const char test_ws_name[] = "bpf_selftest_ws";
static bool test_ws_created;

/*
 * Creates a new wakeup source by writing to /sys/power/wake_lock.
 * This lock persists until explicitly unlocked.
 */
static int lock_ws(const char *name)
{
	int fd;
	ssize_t bytes;

	fd = open("/sys/power/wake_lock", O_WRONLY);
	if (!ASSERT_OK_FD(fd, "open /sys/power/wake_lock"))
		return -1;

	bytes = write(fd, name, strlen(name));
	close(fd);
	if (!ASSERT_EQ(bytes, strlen(name), "write to wake_lock"))
		return -1;

	return 0;
}

/*
 * Destroys the ws by writing the same name to /sys/power/wake_unlock.
 */
static void unlock_ws(const char *name)
{
	int fd;

	fd = open("/sys/power/wake_unlock", O_WRONLY);
	if (!ASSERT_OK_FD(fd, "open /sys/power/wake_unlock"))
		goto cleanup;

	write(fd, name, strlen(name));

cleanup:
	if (fd)
		close(fd);
}

/*
 * Setups for testing ws iterators. Will run once prior to suite of tests.
 */
static int setup_test_ws(void)
{
	if (lock_ws(test_ws_name))
		return -1;
	test_ws_created = true;

	return 0;
}

/*
 * Tears down and cleanups testing ws iterators. WIll run once after the suite
 * of tests.
 */
static void teardown_test_ws(void)
{
	if (!test_ws_created)
		return;
	unlock_ws(test_ws_name);
	test_ws_created = false;
}

struct WakeupSourceInfo {
	char name[WAKEUP_SOURCE_NAME_LEN];
	unsigned long active_count;
	long active_time_ms;
	unsigned long event_count;
	unsigned long expire_count;
	long last_change_ms;
	long max_time_ms;
	long prevent_sleep_time_ms;
	long total_time_ms;
	unsigned long wakeup_count;
};

/*
 * Reads and parses one wakeup_source record from the iterator file.
 * A record is a single space-delimited line.
 * Returns true on success, false on EOF. Asserts internally on errors.
 */
static bool read_ws_info(FILE *iter_file, struct WakeupSourceInfo *ws_info,
			 char **line)
{
	size_t linesize;
	int items;

	if (getline(line, &linesize, iter_file) == -1)
		return false;

	(*line)[strcspn(*line, "\n")] = 0;

	items = sscanf(*line, "%s %lu %ld %lu %lu %ld %ld %ld %ld %lu",
		       ws_info->name, &ws_info->active_count,
		       &ws_info->active_time_ms, &ws_info->event_count,
		       &ws_info->expire_count, &ws_info->last_change_ms,
		       &ws_info->max_time_ms, &ws_info->prevent_sleep_time_ms,
		       &ws_info->total_time_ms, &ws_info->wakeup_count);

	if (!ASSERT_EQ(items, 10, "read wakeup source info"))
		return false;

	if (!ASSERT_LT(strlen(ws_info->name), WAKEUP_SOURCE_NAME_LEN,
		       "name length"))
		return false;

	return true;
}

static int get_ws_iter_stream(struct wakeup_source_iter *skel, int *iter_fd,
			      FILE **iter_file)
{
	*iter_fd = bpf_iter_create(
			bpf_link__fd(skel->links.wakeup_source_collector));
	if (!ASSERT_OK_FD(*iter_fd, "iter_create"))
		return -1;

	*iter_file = fdopen(*iter_fd, "r");
	if (!ASSERT_OK_PTR(*iter_file, "fdopen"))
		return -1;

	return 0;
}

static void subtest_ws_iter_check_active_count(struct wakeup_source_iter *skel)
{
	static const char subtest_ws_name[] = "bpf_selftest_ws_active_count";
	const int lock_unlock_cycles = 5;
	struct WakeupSourceInfo ws_info;
	char *line = NULL;
	bool found_ws = false;
	FILE *iter_file = NULL;
	int iter_fd = -1;
	int i;

	for (i = 0; i < lock_unlock_cycles; i++) {
		if (!ASSERT_OK(lock_ws(subtest_ws_name), "lock_ws"))
			goto cleanup;
		unlock_ws(subtest_ws_name);
	}

	if (!get_ws_iter_stream(skel, &iter_fd, &iter_file))
		goto cleanup;

	while (read_ws_info(iter_file, &ws_info, &line)) {
		if (strcmp(ws_info.name, subtest_ws_name) == 0) {
			found_ws = true;
			ASSERT_EQ(ws_info.active_count, lock_unlock_cycles,
				  "active_count check");
			ASSERT_EQ(ws_info.wakeup_count, lock_unlock_cycles,
				  "wakeup_count check");
			break;
		}
	}

	ASSERT_TRUE(found_ws, "found active_count test ws");

	free(line);
cleanup:
	if (iter_file)
		fclose(iter_file);
	else if (iter_fd >= 0)
		close(iter_fd);
}

static void subtest_ws_iter_check_sleep_times(struct wakeup_source_iter *skel)
{
	bool found_test_ws = false;
	struct WakeupSourceInfo ws_info;
	char *line = NULL;
	FILE *iter_file;
	int iter_fd;

	if (!get_ws_iter_stream(skel, &iter_fd, &iter_file))
		goto cleanup;

	while (read_ws_info(iter_file, &ws_info, &line)) {
		if (strcmp(ws_info.name, test_ws_name) == 0) {
			found_test_ws = true;
			ASSERT_GT(ws_info.last_change_ms, 0,
				  "Expected non-zero last change");
			ASSERT_GE(ws_info.active_time_ms, TEST_SLEEP_MS,
				  "Expected active time >= TEST_SLEEP_MS");
			ASSERT_GE(ws_info.max_time_ms, TEST_SLEEP_MS,
				  "Expected max time >= TEST_SLEEP_MS");
			ASSERT_GE(ws_info.total_time_ms, TEST_SLEEP_MS,
				  "Expected total time >= TEST_SLEEP_MS");
			break;
		}
	}

	ASSERT_TRUE(found_test_ws, "found_test_ws");

	free(line);
cleanup:
	if (iter_file)
		fclose(iter_file);
	else if (iter_fd >= 0)
		close(iter_fd);
}

static void subtest_ws_iter_check_no_infinite_reads(
		struct wakeup_source_iter *skel)
{
	int iter_fd;
	char buf[256];

	iter_fd = bpf_iter_create(bpf_link__fd(skel->links.wakeup_source_collector));
	if (!ASSERT_OK_FD(iter_fd, "iter_create"))
		return;

	while (read(iter_fd, buf, sizeof(buf)) > 0)
		;

	/* Final read should return 0 */
	ASSERT_EQ(read(iter_fd, buf, sizeof(buf)), 0, "read");

	close(iter_fd);
}

static void subtest_ws_iter_check_open_coded(struct wakeup_source_iter *skel,
					     int map_fd)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	char key[WAKEUP_SOURCE_NAME_LEN] = {0};
	int err, fd;
	bool found = false;

	fd = bpf_program__fd(skel->progs.iter_ws_for_each);

	err = bpf_prog_test_run_opts(fd, &topts);
	if (!ASSERT_OK(err, "test_run_opts err"))
		return;
	if (!ASSERT_OK(topts.retval, "test_run_opts retval"))
		return;

	strncpy(key, test_ws_name, WAKEUP_SOURCE_NAME_LEN - 1);

	if (!ASSERT_OK(bpf_map_lookup_elem(map_fd, key, &found),
		       "lookup test_ws_name"))
		return;

	ASSERT_TRUE(found, "found test ws via bpf_for_each");
}

void test_wakeup_source_iter(void)
{
	struct wakeup_source_iter *skel = NULL;
	int map_fd;
	const bool found_val = false;
	char key[WAKEUP_SOURCE_NAME_LEN] = {0};

	if (geteuid() != 0) {
		fprintf(stderr,
			"Skipping wakeup_source_iter test, requires root\n");
		test__skip();
		return;
	}

	skel = wakeup_source_iter__open_and_load();
	if (!ASSERT_OK_PTR(skel, "wakeup_source_iter__open_and_load"))
		return;

	map_fd = bpf_map__fd(skel->maps.test_ws_hash);
	if (!ASSERT_OK_FD(map_fd, "map_fd"))
		goto destroy_skel;

	/* Copy test name to key buffer, ensuring it's zero-padded */
	strncpy(key, test_ws_name, WAKEUP_SOURCE_NAME_LEN - 1);

	if (!ASSERT_OK(bpf_map_update_elem(map_fd, key, &found_val, BPF_ANY),
		       "insert test_ws_name"))
		goto destroy_skel;

	if (!ASSERT_OK(setup_test_ws(), "setup_test_ws"))
		goto destroy;

	if (!ASSERT_OK(wakeup_source_iter__attach(skel), "skel_attach"))
		goto destroy;

	/*
	 * Sleep on O(ms) to ensure that time stats' resolution isn't lost when
	 * converting from ns to ms
	 */
	usleep(TEST_SLEEP_US);

	if (test__start_subtest("active_count"))
		subtest_ws_iter_check_active_count(skel);
	if (test__start_subtest("sleep_times"))
		subtest_ws_iter_check_sleep_times(skel);
	if (test__start_subtest("no_infinite_reads"))
		subtest_ws_iter_check_no_infinite_reads(skel);
	if (test__start_subtest("open_coded"))
		subtest_ws_iter_check_open_coded(skel, map_fd);

destroy:
	teardown_test_ws();
destroy_skel:
	wakeup_source_iter__destroy(skel);
}
