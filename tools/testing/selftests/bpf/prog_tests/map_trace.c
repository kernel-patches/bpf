// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Google */
#include <test_progs.h>

#include "bpf_map_trace.skel.h"
#include "progs/bpf_map_trace_common.h"

#include <sys/mount.h>
#include <sys/stat.h>

enum BoolOrErr {
	TRUE = 0,
	FALSE = 1,
	ERROR = 2,
};

enum BoolOrErr percpu_key_is_set(struct bpf_map *map, uint32_t map_key)
{
	int num_cpus = libbpf_num_possible_cpus();
	uint64_t *percpu_map_val = NULL;
	int map_fd = bpf_map__fd(map);
	enum BoolOrErr ret = ERROR;
	int err;
	int i;

	if (!ASSERT_GE(num_cpus, 1, "get number of cpus"))
		goto out;

	percpu_map_val = malloc(sizeof(*percpu_map_val) * num_cpus);
	if (!ASSERT_NEQ(percpu_map_val, NULL, "allocate percpu map array"))
		goto out;

	err = bpf_map_lookup_elem(map_fd, &map_key, percpu_map_val);
	if (!ASSERT_EQ(err, 0, "map lookup update_elem"))
		goto out;

	ret = FALSE;
	for (i = 0; i < num_cpus; i++)
		if (percpu_map_val[i] != 0)
			ret = TRUE;

out:
	if (percpu_map_val != NULL)
		free(percpu_map_val);

	return ret;
}

enum BoolOrErr key_is_set(struct bpf_map *map, uint32_t map_key)
{
	int map_fd = bpf_map__fd(map);
	uint32_t map_val;
	int rc;

	rc = bpf_map_lookup_elem(map_fd, &map_key, &map_val);
	if (!ASSERT_EQ(rc, 0, "array map lookup update_elem"))
		return ERROR;

	return (map_val == 0 ? FALSE : TRUE);
}

void verify_map_contents(struct bpf_map_trace *skel)
{
	enum BoolOrErr rc_or_err;
	struct bpf_map *map;

	map = skel->maps.array_map;
	rc_or_err = key_is_set(map, ACCESS_LOC__TRACE_UPDATE);
	if (!ASSERT_EQ(rc_or_err, TRUE, "array map updates are traced"))
		return;
	rc_or_err = key_is_set(map, ACCESS_LOC__TRACE_DELETE);
	if (!ASSERT_EQ(rc_or_err, FALSE, "array map deletions are not traced"))
		return;

	map = skel->maps.percpu_array_map;
	rc_or_err = percpu_key_is_set(map, ACCESS_LOC__TRACE_UPDATE);
	if (!ASSERT_EQ(rc_or_err, TRUE, "percpu array map updates are traced"))
		return;
	rc_or_err = percpu_key_is_set(map, ACCESS_LOC__TRACE_DELETE);
	if (!ASSERT_EQ(rc_or_err, FALSE,
		       "percpu array map deletions are not traced"))
		return;

	map = skel->maps.hash_map;
	rc_or_err = key_is_set(map, ACCESS_LOC__TRACE_UPDATE);
	if (!ASSERT_EQ(rc_or_err, TRUE, "hash map updates are traced"))
		return;
	rc_or_err = key_is_set(map, ACCESS_LOC__TRACE_DELETE);
	if (!ASSERT_EQ(rc_or_err, TRUE, "hash map deletions are traced"))
		return;

	map = skel->maps.percpu_hash_map;
	rc_or_err = percpu_key_is_set(map, ACCESS_LOC__TRACE_UPDATE);
	if (!ASSERT_EQ(rc_or_err, TRUE, "percpu hash map updates are traced"))
		return;
	rc_or_err = percpu_key_is_set(map, ACCESS_LOC__TRACE_DELETE);
	if (!ASSERT_EQ(rc_or_err, TRUE,
		       "percpu hash map deletions are traced"))
		return;

	map = skel->maps.lru_hash_map;
	rc_or_err = key_is_set(map, ACCESS_LOC__TRACE_UPDATE);
	if (!ASSERT_EQ(rc_or_err, TRUE, "lru_hash map updates are traced"))
		return;
	rc_or_err = key_is_set(map, ACCESS_LOC__TRACE_DELETE);
	if (!ASSERT_EQ(rc_or_err, TRUE, "lru_hash map deletions are traced"))
		return;

	map = skel->maps.percpu_lru_hash_map;
	rc_or_err = percpu_key_is_set(map, ACCESS_LOC__TRACE_UPDATE);
	if (!ASSERT_EQ(rc_or_err, TRUE,
		       "percpu lru hash map updates are traced"))
		return;
	rc_or_err = percpu_key_is_set(map, ACCESS_LOC__TRACE_DELETE);
	if (!ASSERT_EQ(rc_or_err, TRUE,
		       "percpu lru hash map deletions are traced"))
		return;
}

void map_trace_test(void)
{
	struct bpf_map_trace *skel;
	ssize_t bytes_written;
	char write_buf = 'a';
	int write_fd = -1;
	int rc;

	/*
	 * Load and attach programs.
	 */
	skel = bpf_map_trace__open_and_load();
	if (!ASSERT_NEQ(skel, NULL, "open/load skeleton"))
		return;

	rc = bpf_map_trace__attach(skel);
	if (!ASSERT_EQ(rc, 0, "attach skeleton"))
		goto out;

	/*
	 * Invoke core BPF program.
	 */
	write_fd = open("/tmp/map_trace_test_file", O_CREAT | O_WRONLY);
	if (!ASSERT_GE(rc, 0, "open tmp file for writing"))
		goto out;

	bytes_written = write(write_fd, &write_buf, sizeof(write_buf));
	if (!ASSERT_EQ(bytes_written, sizeof(write_buf), "write to tmp file"))
		return;

	/*
	 * Verify that tracing programs were invoked as expected.
	 */
	verify_map_contents(skel);

out:
	if (skel)
		bpf_map_trace__destroy(skel);
	if (write_fd != -1)
		close(write_fd);
}

void test_map_trace(void)
{
	map_trace_test();
}

