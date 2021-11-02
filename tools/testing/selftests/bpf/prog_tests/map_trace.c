// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Google */
#include <test_progs.h>

#include "bpf_map_trace.skel.h"
#include "bpf_map_trace_real_world_migration.skel.h"
#include "bpf_map_trace_real_world_new.skel.h"
#include "bpf_map_trace_real_world_old.skel.h"
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

int real_world_example__attach_migration(
		struct bpf_map_trace_real_world_migration *migration_skel,
		struct bpf_link **iter_link,
		struct bpf_link **map_trace_link_update,
		struct bpf_link **map_trace_link_delete)
{
	union bpf_iter_link_info iter_link_info;
	struct bpf_iter_attach_opts iter_opts;
	int64_t error;

	*map_trace_link_update = bpf_program__attach(
			migration_skel->progs.copy_on_write__update);
	error = libbpf_get_error(map_trace_link_update);
	if (!ASSERT_EQ(error, 0,
		       "copy_on_write update bpf_program__attach failure"))
		return 1;

	*map_trace_link_delete = bpf_program__attach(
			migration_skel->progs.copy_on_write__delete);
	error = libbpf_get_error(map_trace_link_delete);
	if (!ASSERT_EQ(error, 0,
		       "copy_on_write update bpf_program__delete failure"))
		return 1;

	memset(&iter_link_info, 0, sizeof(iter_link_info));
	iter_link_info.map.map_fd = bpf_map__fd(migration_skel->maps.old_map);

	memset(&iter_opts, 0, sizeof(iter_opts));
	iter_opts.sz = sizeof(iter_opts);
	iter_opts.link_info = &iter_link_info;
	iter_opts.link_info_len = sizeof(iter_link_info);
	*iter_link = bpf_program__attach_iter(
			migration_skel->progs.bulk_migration, &iter_opts);
	error = libbpf_get_error(iter_link);
	if (!ASSERT_EQ(error, 0, "bpf_program__attach_iter failure"))
		return 1;

	return 0;
}

int open_and_write_files(const char *path, size_t num_files)
{
	int *fds = malloc(sizeof(int) * num_files);
	ssize_t bytes_written;
	const char buf = 'a';
	size_t i, j;
	int ret = 0;

	if (fds == NULL)
		return 1;

	for (i = 0; i < num_files; i++) {
		fds[i] = open(path, O_WRONLY | O_CREAT);

		if (fds[i] < 0) {
			ret = 2;
			break;
		}
		bytes_written = write(fds[i], &buf, sizeof(buf));
		if (bytes_written != sizeof(buf)) {
			ret = 3;
			break;
		}
	}
	for (j = 0; j < i; j++)
		close(fds[j]);
	return ret;
}

void real_world_example(void)
{
	struct bpf_map_trace_real_world_migration *migration_skel = NULL;
	int file_fd_should_write = -1, file_fd_should_not_write = -1;
	struct bpf_map_trace_real_world_new *new_skel = NULL;
	struct bpf_map_trace_real_world_old *old_skel = NULL;
	struct bpf_link *map_trace_link_update = NULL;
	struct bpf_link *map_trace_link_delete = NULL;
	struct bpf_link *iter_link = NULL;
	const bool enable_filtering = 1;
	const uint32_t pid = getpid();
	uint32_t max_open_files;
	char file_buf = 'a';
	int iter_fd = -1;
	char iter_buf[1];
	int rc;

	/*
	 * Begin by loading and attaching the old version of our program.
	 */
	old_skel = bpf_map_trace_real_world_old__open_and_load();
	if (!ASSERT_NEQ(old_skel, NULL, "open/load old skeleton"))
		return;
	rc = bpf_map_trace_real_world_old__attach(old_skel);
	if (!ASSERT_EQ(rc, 0, "attach old skeleton")) {
		fprintf(stderr, "Failed to attach skeleton: %d\n", errno);
		goto out;
	}
	rc = bpf_map_update_elem(bpf_map__fd(old_skel->maps.filtered_pids),
				 &pid, &enable_filtering, /*flags=*/0);
	if (!ASSERT_EQ(rc, 0, "configure process to be filtered"))
		return;
	if (!ASSERT_EQ(open_and_write_files("/tmp/tst_file", 1), 0,
		       "program allows writing a single new file"))
		goto out;
	max_open_files = bpf_map__max_entries(old_skel->maps.allow_reads);
	if (!ASSERT_NEQ(open_and_write_files("/tmp/tst_file",
					     max_open_files + 1), 0,
		       "program blocks writing too many new files"))
		goto out;

	/*
	 * Then load the new version of the program.
	 */
	new_skel = bpf_map_trace_real_world_new__open_and_load();
	if (!ASSERT_NEQ(new_skel, NULL, "open/load new skeleton"))
		goto out;

	/*
	 * Hook up the migration programs. This gives the old map
	 * copy-on-write semantics.
	 */
	migration_skel = bpf_map_trace_real_world_migration__open();
	if (!ASSERT_NEQ(migration_skel, NULL, "open migration skeleton"))
		goto out;
	rc = bpf_map__reuse_fd(migration_skel->maps.old_map,
			       bpf_map__fd(old_skel->maps.allow_reads));
	if (!ASSERT_EQ(rc, 0, "reuse old map fd"))
		goto out;
	rc = bpf_map__reuse_fd(migration_skel->maps.new_map,
			       bpf_map__fd(new_skel->maps.allow_reads));
	if (!ASSERT_EQ(rc, 0, "reuse new map fd"))
		goto out;
	rc = bpf_map_trace_real_world_migration__load(migration_skel);
	if (!ASSERT_EQ(rc, 0, "load migration skeleton"))
		goto out;
	rc = real_world_example__attach_migration(migration_skel,
						  &iter_link,
						  &map_trace_link_update,
						  &map_trace_link_delete);
	if (!ASSERT_EQ(rc, 0, "attach migration programs"))
		goto out;

	/*
	 * Simulated race condition type 1: An application opens an fd before
	 * bulk transfer and closes it after.
	 */
	file_fd_should_not_write = open("/tmp/tst_file", O_WRONLY | O_CREAT);
	if (!ASSERT_GE(file_fd_should_not_write, 0,
		       "open file before bulk migration"))
		goto out;

	/*
	 * Perform bulk transfer.
	 */
	iter_fd = bpf_iter_create(bpf_link__fd(iter_link));
	if (!ASSERT_GE(iter_fd, 0, "create iterator"))
		goto out;
	rc = read(iter_fd, &iter_buf, sizeof(iter_buf));
	if (!ASSERT_EQ(rc, 0, "execute map iterator"))
		goto out;
	rc = bpf_map_update_elem(bpf_map__fd(new_skel->maps.filtered_pids),
				 &pid, &enable_filtering, /*flags=*/0);
	if (!ASSERT_EQ(rc, 0, "configure process to be filtered"))
		goto out;

	/*
	 * Simulated race condition type 1 (continued). This close() does not
	 * propagate to the new map without copy-on-write semantics, so it
	 * would occupy a spot in the map until our app happens to close an fd
	 * with the same number. This would subtly degrade the contract with
	 * the application.
	 */
	close(file_fd_should_not_write);
	file_fd_should_not_write = -1;

	/*
	 * Simulated race condition type 2: An application opens a file
	 * descriptor after bulk transfer. This openat() does not propagate to
	 * the new map without copy-on-write, so our app would not be able to
	 * write to it.
	 */
	file_fd_should_write = open("/tmp/tst_file", O_WRONLY | O_CREAT);
	if (!ASSERT_GE(file_fd_should_write, 0,
		       "open file after bulk migration"))
		goto out;

	/*
	 * State is migrated. Load new programs.
	 */
	rc = bpf_map_trace_real_world_new__attach(new_skel);
	if (!ASSERT_EQ(rc, 0, "failed to attach new programs"))
		goto out;

	/*
	 * Unload migration progs.
	 */
	close(iter_fd);
	iter_fd = -1;
	bpf_link__destroy(map_trace_link_update);
	map_trace_link_update = NULL;
	bpf_link__destroy(map_trace_link_delete);
	map_trace_link_delete = NULL;
	bpf_link__destroy(iter_link);
	iter_link = NULL;
	bpf_map_trace_real_world_migration__destroy(migration_skel);
	migration_skel = NULL;

	/*
	 * Unload old programs.
	 */
	bpf_map_trace_real_world_old__destroy(old_skel);
	old_skel = NULL;

	if (!ASSERT_EQ(open_and_write_files("/tmp/tst_file", 1), 0,
		       "program allows writing a single new file"))
		goto out;
	max_open_files = bpf_map__max_entries(new_skel->maps.allow_reads);
	if (!ASSERT_NEQ(open_and_write_files("/tmp/tst_file",
					     max_open_files + 1), 0,
		       "program blocks writing too many new files"))
		goto out;
	/*
	 * Simulated race condition type 2 (continued): If we didn't do
	 * copy-on-write, this would be expected to fail, since the FD would
	 * not be in the new map.
	 */
	rc = write(file_fd_should_write, &file_buf, sizeof(file_buf));
	if (!ASSERT_EQ(rc, sizeof(file_buf),
		       "migrated program allows writing to file opened before migration"))
		goto out;

out:
	if (old_skel)
		bpf_map_trace_real_world_old__destroy(old_skel);
	if (new_skel)
		bpf_map_trace_real_world_new__destroy(new_skel);
	if (migration_skel)
		bpf_map_trace_real_world_migration__destroy(migration_skel);
	if (map_trace_link_update)
		bpf_link__destroy(map_trace_link_update);
	if (map_trace_link_delete)
		bpf_link__destroy(map_trace_link_delete);
	if (iter_link)
		bpf_link__destroy(iter_link);
	if (iter_fd > -1)
		close(iter_fd);
	if (file_fd_should_write > -1)
		close(file_fd_should_write);
	if (file_fd_should_not_write > -1)
		close(file_fd_should_not_write);
}

void test_map_trace(void)
{
	map_trace_test();
	real_world_example();
}

