// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */
#include <test_progs.h>
#include <string.h>
#include <stdio.h>
#include "rhash.skel.h"
#include "bpf_iter_bpf_rhash_map.skel.h"
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <network_helpers.h>

static void rhash_run(const char *prog_name)
{
	struct rhash *skel;
	struct bpf_program *prog;
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int err;

	skel = rhash__open();
	if (!ASSERT_OK_PTR(skel, "rhash__open"))
		return;

	prog = bpf_object__find_program_by_name(skel->obj, prog_name);
	if (!ASSERT_OK_PTR(prog, "bpf_object__find_program_by_name"))
		goto cleanup;
	bpf_program__set_autoload(prog, true);

	err = rhash__load(skel);
	if (!ASSERT_OK(err, "skel_load"))
		goto cleanup;

	err = bpf_prog_test_run_opts(bpf_program__fd(prog), &opts);
	if (!ASSERT_OK(err, "prog run"))
		goto cleanup;

	if (!ASSERT_OK(skel->bss->err, "bss->err"))
		goto cleanup;

cleanup:
	rhash__destroy(skel);
}

struct lock_thread_args {
	int prog_fd;
	int map_fd;
};

struct lock_elem {
	struct bpf_spin_lock lock;
	int var[16];
};

static void *spin_lock_thread(void *arg)
{
	struct lock_thread_args *args = arg;
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.repeat = 10000,
	);
	int err;

	err = bpf_prog_test_run_opts(args->prog_fd, &topts);
	if (err || topts.retval)
		return (void *)1;

	return (void *)0;
}

static void *parallel_map_access(void *arg)
{
	struct lock_thread_args *args = arg;
	int i, j, key = 0;
	int err;
	struct lock_elem val;

	for (i = 0; i < 10000; i++) {
		err = bpf_map_lookup_elem_flags(args->map_fd, &key, &val, BPF_F_LOCK);
		if (err)
			return (void *)1;
		if (val.lock.val)
			return (void *)1;
		for (j = 1; j < 16; j++) {
			if (val.var[j] != val.var[0])
				return (void *)1;
		}
	}

	return (void *)0;
}

static void rhash_spin_lock_test(void)
{
	struct lock_thread_args args;
	struct rhash *skel;
	struct lock_elem val = {};
	pthread_t thread_id[4];
	int err, key = 0, i;
	void *ret;

	skel = rhash__open_and_load();
	if (!ASSERT_OK_PTR(skel, "rhash__open_and_load"))
		return;

	args.prog_fd = bpf_program__fd(skel->progs.test_rhash_spin_lock);
	args.map_fd = bpf_map__fd(skel->maps.rhmap_lock);

	/* Insert initial element with BPF_F_LOCK */
	err = bpf_map_update_elem(args.map_fd, &key, &val, BPF_F_LOCK);
	if (!ASSERT_OK(err, "initial update"))
		goto cleanup;

	/* Spawn 2 threads running BPF program (uses bpf_spin_lock) */
	for (i = 0; i < 2; i++)
		if (!ASSERT_OK(pthread_create(&thread_id[i], NULL,
					      &spin_lock_thread, &args),
			       "pthread_create spin_lock"))
			goto cleanup;

	/* Spawn 2 threads doing parallel map access with BPF_F_LOCK */
	for (i = 2; i < 4; i++)
		if (!ASSERT_OK(pthread_create(&thread_id[i], NULL,
					      &parallel_map_access, &args),
			       "pthread_create parallel_map_access"))
			goto cleanup;

	/* Wait for all threads */
	for (i = 0; i < 4; i++)
		if (!ASSERT_OK(pthread_join(thread_id[i], &ret), "pthread_join") ||
		    !ASSERT_OK((long)ret, "thread ret"))
			goto cleanup;

cleanup:
	rhash__destroy(skel);
}

struct iter_thread_args {
	int map_fd;
	int stop;
	int error;
};

static void *get_next_key_thread(void *arg)
{
	struct iter_thread_args *args = arg;
	int key, next_key;
	int i = 0;

	for (i = 0; i < 1000; i++) {
		if (READ_ONCE(args->stop))
			break;

		if (bpf_map_get_next_key(args->map_fd, NULL, &next_key) != 0) {
			WRITE_ONCE(args->error, 1);
			continue;
		}

		key = next_key;
		while (bpf_map_get_next_key(args->map_fd, &key, &next_key) == 0)
			key = next_key;
	}

	return (void *)0;
}

static void *modifier_thread(void *arg)
{
	struct iter_thread_args *args = arg;
	int key, value;
	int i;

	for (i = 0; i < 10000; i++) {
		if (READ_ONCE(args->stop))
			break;

		key = i;
		value = i;
		if (bpf_map_update_elem(args->map_fd, &key, &value, BPF_ANY))
			WRITE_ONCE(args->error, 1);
	}

	return (void *)0;
}

static void rhash_get_next_key_stress_test(void)
{
	struct iter_thread_args args = {};
	struct rhash *skel;
	pthread_t iter_threads[2];
	pthread_t mod_threads[2];
	int key, value;
	int err, i;
	void *ret;

	skel = rhash__open_and_load();
	if (!ASSERT_OK_PTR(skel, "rhash__open_and_load"))
		return;

	args.map_fd = bpf_map__fd(skel->maps.rhmap_iter);
	args.stop = 0;
	args.error = 0;

	/* Pre-populate map */
	for (i = 0; i < 50; i++) {
		key = i;
		value = i;
		err = bpf_map_update_elem(args.map_fd, &key, &value, BPF_NOEXIST);
		if (!ASSERT_OK(err, "initial insert"))
			goto cleanup;
	}

	/* Iterator threads */
	for (i = 0; i < 2; i++)
		if (!ASSERT_OK(pthread_create(&iter_threads[i], NULL,
					      &get_next_key_thread, &args),
			       "pthread_create iter"))
			goto cleanup;

	/* Modifier threads */
	for (i = 0; i < 2; i++)
		if (!ASSERT_OK(pthread_create(&mod_threads[i], NULL,
					      &modifier_thread, &args),
			       "pthread_create mod"))
			goto cleanup;

	/* Wait for modifier threads to finish */
	for (i = 0; i < 2; i++)
		pthread_join(mod_threads[i], &ret);

	/* Signal iterator threads to stop */
	WRITE_ONCE(args.stop, 1);

	/* Wait for iterator threads */
	for (i = 0; i < 2; i++)
		if (!ASSERT_OK(pthread_join(iter_threads[i], &ret), "pthread_join iter") ||
		    !ASSERT_OK((long)ret, "iter thread ret"))
			goto cleanup;

	ASSERT_EQ(args.error, 0, "no infinite loop");

cleanup:
	rhash__destroy(skel);
}

static void iterate_all(int map_fd, int num_elems)
{
	int *visited, key, next_key, i, err;

	visited = calloc(num_elems, sizeof(int));
	if (!ASSERT_TRUE(visited, "calloc"))
		return;
	memset(visited, 0, num_elems * sizeof(int));

	for (err = bpf_map_get_next_key(map_fd, NULL, &next_key); err == 0;
	     err = bpf_map_get_next_key(map_fd, &key, &next_key)) {
		key = next_key;
		if (ASSERT_TRUE(key >= 0 && key < num_elems, "key valid"))
			visited[key] += 1;
	}

	for (i = 0; i < num_elems; i++)
		ASSERT_EQ(visited[i], 1, "element visited");

	free(visited);
}

static void rhash_get_next_key_resize_test(void)
{
	struct rhash *skel;
	int key, next_key, value;
	int map_fd;
	int err, i;

	skel = rhash__open_and_load();
	if (!ASSERT_OK_PTR(skel, "rhash__open_and_load"))
		return;

	map_fd = bpf_map__fd(skel->maps.rhmap_iter);

	/* Phase 1: small table, no resize - verify completeness */
	for (i = 0; i < 4; i++) {
		key = i;
		value = i;
		err = bpf_map_update_elem(map_fd, &key, &value, BPF_NOEXIST);
		if (!ASSERT_OK(err, "insert small"))
			goto cleanup;
	}
	iterate_all(map_fd, 4);

	/* Phase 2: trigger resize by inserting more elements */
	for (i = 4; i < 100; i++) {
		key = i;
		value = i;
		err = bpf_map_update_elem(map_fd, &key, &value, BPF_NOEXIST);
		if (!ASSERT_OK(err, "insert resize"))
			goto cleanup;

		/* Full iteration during resize - verify all code paths are safe */
		for (err = bpf_map_get_next_key(map_fd, NULL, &next_key); err == 0;
		     err = bpf_map_get_next_key(map_fd, &key, &next_key)) {
			key = next_key;
		}
	}

	/* Phase 3: after resize settled - verify completeness */
	iterate_all(map_fd, 100);

cleanup:
	rhash__destroy(skel);
}

static void rhash_iter_test(void)
{
	DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	struct bpf_iter_bpf_rhash_map *skel;
	int err, i, len, map_fd, iter_fd;
	union bpf_iter_link_info linfo;
	u32 expected_key_sum = 0, key;
	struct bpf_link *link;
	u64 val = 0;
	char buf[64];

	skel = bpf_iter_bpf_rhash_map__open();
	if (!ASSERT_OK_PTR(skel, "bpf_iter_bpf_rhash_map__open"))
		return;

	err = bpf_iter_bpf_rhash_map__load(skel);
	if (!ASSERT_OK(err, "bpf_iter_bpf_rhash_map__load"))
		goto out;

	map_fd = bpf_map__fd(skel->maps.rhashmap);

	/* Populate map with test data */
	for (i = 0; i < 64; i++) {
		key = i + 1;
		expected_key_sum += key;

		err = bpf_map_update_elem(map_fd, &key, &val, BPF_NOEXIST);
		if (!ASSERT_OK(err, "map_update"))
			goto out;
	}

	memset(&linfo, 0, sizeof(linfo));
	linfo.map.map_fd = map_fd;
	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);

	link = bpf_program__attach_iter(skel->progs.dump_bpf_rhash_map, &opts);
	if (!ASSERT_OK_PTR(link, "attach_iter"))
		goto out;

	iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (!ASSERT_GE(iter_fd, 0, "create_iter"))
		goto free_link;

	do {
		len = read(iter_fd, buf, sizeof(buf));
	} while (len > 0);

	ASSERT_EQ(skel->bss->key_sum, expected_key_sum, "key_sum");
	ASSERT_EQ(skel->bss->elem_count, 64, "elem_count");

	close(iter_fd);

free_link:
	bpf_link__destroy(link);
out:
	bpf_iter_bpf_rhash_map__destroy(skel);
}

/*
 * Test seq_file overflow handling for BPF iterator over resizable hashmap.
 *
 * The BPF program writes print_count * 8 bytes per element, configured so
 * that a single element's output nearly fills the seq_file buffer (8 pages).
 * With multiple elements, the buffer overflows mid-element, triggering
 * seq_file's restart mechanism: it discards the partial output, enlarges or
 * flushes the buffer, and re-invokes the BPF program starting from the
 * element that caused the overflow.
 *
 * Insert few elements to avoid triggering rhashtable resize, then verify:
 * - All elements are seen (unique_elem_count == num_elems)
 * - Overflow occurred (total_visits > unique_elem_count)
 * - Output is consistent (each chunk of print_count u64s has the same value)
 */
static void rhash_iter_overflow_test(void)
{
	DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	struct bpf_iter_bpf_rhash_map *skel;
	u32 total_read_len, expected_read_len, write_len, num_elems = 4;
	int err, i, j, len, map_fd, iter_fd;
	union bpf_iter_link_info linfo;
	struct bpf_link *link;
	char *buf;

	skel = bpf_iter_bpf_rhash_map__open();
	if (!ASSERT_OK_PTR(skel, "bpf_iter_bpf_rhash_map__open"))
		return;

	write_len = sysconf(_SC_PAGE_SIZE) * 8;
	skel->bss->print_count = (write_len - 8) / 8;
	expected_read_len = num_elems * (write_len - 8);

	err = bpf_iter_bpf_rhash_map__load(skel);
	if (!ASSERT_OK(err, "bpf_iter_bpf_rhash_map__load"))
		goto out;

	map_fd = bpf_map__fd(skel->maps.rhashmap);

	for (i = 0; i < num_elems; i++) {
		__u64 val = i;

		err = bpf_map_update_elem(map_fd, &i, &val, BPF_NOEXIST);
		if (!ASSERT_OK(err, "map_update"))
			goto out;
	}

	memset(&linfo, 0, sizeof(linfo));
	linfo.map.map_fd = map_fd;
	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);

	link = bpf_program__attach_iter(skel->progs.dump_bpf_rhash_map_overflow, &opts);
	if (!ASSERT_OK_PTR(link, "attach_iter"))
		goto out;

	iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (!ASSERT_GE(iter_fd, 0, "create_iter"))
		goto free_link;

	buf = malloc(expected_read_len);
	if (!ASSERT_OK_PTR(buf, "malloc"))
		goto close_iter;

	total_read_len = 0;
	while ((len = read(iter_fd, buf + total_read_len,
			   expected_read_len - total_read_len)) > 0)
		total_read_len += len;

	ASSERT_OK(len, "len");
	ASSERT_EQ(total_read_len, expected_read_len, "total_read_len");
	ASSERT_EQ(skel->bss->unique_elem_count, num_elems, "unique_elem_count");
	ASSERT_GT(skel->bss->total_visits, skel->bss->unique_elem_count,
		  "overflow_occurred");

	/* Verify each output chunk is internally consistent */
	for (i = 0; i < num_elems; i++) {
		__u64 *val = ((__u64 *)buf) + i * skel->bss->print_count;

		ASSERT_LT(val[0], num_elems, "value_in_range");
		for (j = 1; j < skel->bss->print_count; j++)
			ASSERT_EQ(val[j], val[0], "consistent_value");
	}

	free(buf);
close_iter:
	close(iter_fd);
free_link:
	bpf_link__destroy(link);
out:
	bpf_iter_bpf_rhash_map__destroy(skel);
}

void test_rhash(void)
{
	if (test__start_subtest("test_rhash_lookup_update"))
		rhash_run("test_rhash_lookup_update");

	if (test__start_subtest("test_rhash_update_delete"))
		rhash_run("test_rhash_update_delete");

	if (test__start_subtest("test_rhash_update_elements"))
		rhash_run("test_rhash_update_elements");

	if (test__start_subtest("test_rhash_update_exist"))
		rhash_run("test_rhash_update_exist");

	if (test__start_subtest("test_rhash_update_any"))
		rhash_run("test_rhash_update_any");

	if (test__start_subtest("test_rhash_noexist_duplicate"))
		rhash_run("test_rhash_noexist_duplicate");

	if (test__start_subtest("test_rhash_delete_nonexistent"))
		rhash_run("test_rhash_delete_nonexistent");

	if (test__start_subtest("test_rhash_spin_lock"))
		rhash_spin_lock_test();

	if (test__start_subtest("test_rhash_get_next_key_resize"))
		rhash_get_next_key_resize_test();

	if (test__start_subtest("test_rhash_get_next_key_stress"))
		rhash_get_next_key_stress_test();

	if (test__start_subtest("test_rhash_iter"))
		rhash_iter_test();

	if (test__start_subtest("test_rhash_iter_overflow"))
		rhash_iter_overflow_test();
}
