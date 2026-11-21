// SPDX-License-Identifier: GPL-2.0
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <linux/compiler.h>
#include <linux/kernel.h>
#include "debug.h"
#include "dso.h"
#include "env.h"
#include "map.h"
#include "maps.h"
#include "tests.h"

struct map_def {
	const char *name;
	u64 start;
	u64 end;
};

struct check_maps_cb_args {
	struct map_def *merged;
	unsigned int i;
};

static int check_maps_cb(struct map *map, void *data)
{
	struct check_maps_cb_args *args = data;
	struct map_def *merged = &args->merged[args->i];

	if (map__start(map) != merged->start ||
	    map__end(map) != merged->end ||
	    strcmp(dso__name(map__dso(map)), merged->name) ||
	    refcount_read(map__refcnt(map)) != 1) {
		return 1;
	}
	args->i++;
	return 0;
}

static int failed_cb(struct map *map, void *data __maybe_unused)
{
	pr_debug("\tstart: %" PRIu64 " end: %" PRIu64 " name: '%s' refcnt: %d\n",
		map__start(map),
		map__end(map),
		dso__name(map__dso(map)),
		refcount_read(map__refcnt(map)));

	return 0;
}

static int check_maps(struct map_def *merged, unsigned int size, struct maps *maps)
{
	bool failed = false;

	if (maps__nr_maps(maps) != size) {
		pr_debug("Expected %d maps, got %d", size, maps__nr_maps(maps));
		failed = true;
	} else {
		struct check_maps_cb_args args = {
			.merged = merged,
			.i = 0,
		};
		failed = maps__for_each_map(maps, check_maps_cb, &args);
	}
	if (failed) {
		pr_debug("Expected:\n");
		for (unsigned int i = 0; i < size; i++) {
			pr_debug("\tstart: %" PRIu64 " end: %" PRIu64 " name: '%s' refcnt: 1\n",
				merged[i].start, merged[i].end, merged[i].name);
		}
		pr_debug("Got:\n");
		maps__for_each_map(maps, failed_cb, NULL);
	}
	return failed ? TEST_FAIL : TEST_OK;
}

static int test__maps__merge_in(struct test_suite *t __maybe_unused, int subtest __maybe_unused)
{
	unsigned int i;
	struct map_def bpf_progs[] = {
		{ "bpf_prog_1", 200, 300 },
		{ "bpf_prog_2", 500, 600 },
		{ "bpf_prog_3", 800, 900 },
	};
	struct map_def merged12[] = {
		{ "kcore1",     100,  200 },
		{ "bpf_prog_1", 200,  300 },
		{ "kcore1",     300,  500 },
		{ "bpf_prog_2", 500,  600 },
		{ "kcore1",     600,  800 },
		{ "bpf_prog_3", 800,  900 },
		{ "kcore1",     900, 1000 },
	};
	struct map_def merged3[] = {
		{ "kcore1",      100,  200 },
		{ "bpf_prog_1",  200,  300 },
		{ "kcore1",      300,  500 },
		{ "bpf_prog_2",  500,  600 },
		{ "kcore1",      600,  800 },
		{ "bpf_prog_3",  800,  900 },
		{ "kcore1",      900, 1000 },
		{ "kcore3",     1000, 1100 },
	};
	struct map *map_kcore1, *map_kcore2, *map_kcore3;
	int ret;
	struct perf_env host_env;
	struct machine *machine;
	struct maps *maps;

	perf_env__init(&host_env);
	machine = machine__new_live(&host_env, /*kernel_maps=*/false, getpid());
	maps = maps__new(machine);

	TEST_ASSERT_VAL("failed to create machine", machine);
	TEST_ASSERT_VAL("failed to create maps", maps);

	for (i = 0; i < ARRAY_SIZE(bpf_progs); i++) {
		struct map *map;

		map = dso__new_map(bpf_progs[i].name);
		TEST_ASSERT_VAL("failed to create map", map);

		map__set_start(map, bpf_progs[i].start);
		map__set_end(map, bpf_progs[i].end);
		TEST_ASSERT_VAL("failed to insert map", maps__insert(maps, map) == 0);
		map__put(map);
	}

	map_kcore1 = dso__new_map("kcore1");
	TEST_ASSERT_VAL("failed to create map", map_kcore1);

	map_kcore2 = dso__new_map("kcore2");
	TEST_ASSERT_VAL("failed to create map", map_kcore2);

	map_kcore3 = dso__new_map("kcore3");
	TEST_ASSERT_VAL("failed to create map", map_kcore3);

	/* kcore1 map overlaps over all bpf maps */
	map__set_start(map_kcore1, 100);
	map__set_end(map_kcore1, 1000);

	/* kcore2 map hides behind bpf_prog_2 */
	map__set_start(map_kcore2, 550);
	map__set_end(map_kcore2, 570);

	/* kcore3 map hides behind bpf_prog_3, kcore1 and adds new map */
	map__set_start(map_kcore3, 880);
	map__set_end(map_kcore3, 1100);

	ret = maps__merge_in(maps, map_kcore1);
	TEST_ASSERT_VAL("failed to merge map", !ret);

	ret = check_maps(merged12, ARRAY_SIZE(merged12), maps);
	TEST_ASSERT_VAL("merge check failed", !ret);

	ret = maps__merge_in(maps, map_kcore2);
	TEST_ASSERT_VAL("failed to merge map", !ret);

	ret = check_maps(merged12, ARRAY_SIZE(merged12), maps);
	TEST_ASSERT_VAL("merge check failed", !ret);

	ret = maps__merge_in(maps, map_kcore3);
	TEST_ASSERT_VAL("failed to merge map", !ret);

	ret = check_maps(merged3, ARRAY_SIZE(merged3), maps);
	TEST_ASSERT_VAL("merge check failed", !ret);

	maps__zput(maps);
	map__zput(map_kcore1);
	map__zput(map_kcore2);
	map__zput(map_kcore3);
	machine__delete(machine);
	perf_env__exit(&host_env);
	return TEST_OK;
}

static int test__maps__fixup_overlap_and_insert(struct test_suite *t __maybe_unused,
						int subtest __maybe_unused)
{
	struct map_def initial_maps[] = {
		{ "target_map", 1000, 2000 },
		{ "next_map",   3000, 4000 },
	};
	struct map_def insert_split = { "split_map", 1400, 1600 };
	struct map_def expected_after_split[] = {
		{ "target_map", 1000, 1400 },
		{ "split_map",  1400, 1600 },
		{ "target_map", 1600, 2000 },
		{ "next_map",   3000, 4000 },
	};

	struct map_def insert_eclipse = { "eclipse_map", 2500, 4500 };
	struct map_def expected_final[] = {
		{ "target_map",  1000, 1400 },
		{ "split_map",   1400, 1600 },
		{ "target_map",  1600, 2000 },
		{ "eclipse_map", 2500, 4500 },
		/* "next_map" (3000-4000) is removed */
	};

	struct map *map_split, *map_eclipse;
	int ret;
	unsigned int i;
	struct perf_env host_env;
	struct machine *machine;
	struct maps *maps;

	perf_env__init(&host_env);
	machine = machine__new_live(&host_env, /*kernel_maps=*/false, getpid());
	maps = maps__new(machine);

	TEST_ASSERT_VAL("failed to create machine", machine);
	TEST_ASSERT_VAL("failed to create maps", maps);

	for (i = 0; i < ARRAY_SIZE(initial_maps); i++) {
		struct map *map = dso__new_map(initial_maps[i].name);

		TEST_ASSERT_VAL("failed to create map", map);
		map__set_start(map, initial_maps[i].start);
		map__set_end(map, initial_maps[i].end);
		TEST_ASSERT_VAL("failed to insert map", maps__insert(maps, map) == 0);
		map__put(map);
	}

	// Check splitting.
	map_split = dso__new_map(insert_split.name);
	TEST_ASSERT_VAL("failed to create split map", map_split);
	map__set_start(map_split, insert_split.start);
	map__set_end(map_split, insert_split.end);

	ret = maps__fixup_overlap_and_insert(maps, map_split);
	TEST_ASSERT_VAL("failed to fixup and insert split map", !ret);

	map__zput(map_split);
	ret = check_maps(expected_after_split, ARRAY_SIZE(expected_after_split), maps);
	TEST_ASSERT_VAL("split check failed", !ret);

	// Check cover 1 map with another.
	map_eclipse = dso__new_map(insert_eclipse.name);
	TEST_ASSERT_VAL("failed to create eclipse map", map_eclipse);
	map__set_start(map_eclipse, insert_eclipse.start);
	map__set_end(map_eclipse, insert_eclipse.end);

	ret = maps__fixup_overlap_and_insert(maps, map_eclipse);
	TEST_ASSERT_VAL("failed to fixup and insert eclipse map", !ret);

	map__zput(map_eclipse);
	ret = check_maps(expected_final, ARRAY_SIZE(expected_final), maps);
	TEST_ASSERT_VAL("eclipse check failed", !ret);

	maps__zput(maps);
	machine__delete(machine);
	perf_env__exit(&host_env);
	return TEST_OK;
}

static bool remove_not_keep_cb(struct map *map, void *data)
{
	const char *keep_name = data;

	return strcmp(dso__name(map__dso(map)), keep_name) != 0;
}

static int check_remove_after_end_update(bool swap_order, bool use_by_name,
					 bool use_fixup_end, bool use_remove_maps)
{
	struct perf_env host_env;
	struct machine *machine;
	struct maps *maps;
	struct map *map_a = NULL, *map_b = NULL, *map_keep = NULL, *missing = NULL;
	struct map *map_first, *map_second, *found;
	struct map_def expected_after_first[] = {
		{ "map_same", 1000, use_fixup_end ? 1000 : 1100 },
		{ "z_keep",   1000, 1300 },
	};
	struct map_def expected_after_remove_maps[] = {
		{ "z_keep",   1000, 1300 },
	};
	int ret = TEST_FAIL;

	perf_env__init(&host_env);
	machine = machine__new_live(&host_env, /*kernel_maps=*/false, getpid());
	maps = maps__new(machine);
	if (!machine || !maps)
		goto out_env;

	map_a = dso__new_map("map_same");
	map_b = dso__new_map("map_same");
	map_keep = dso__new_map("z_keep");
	missing = dso__new_map("missing");
	if (!map_a || !map_b || !map_keep || !missing)
		goto out_maps;

	map_first = swap_order ? map_b : map_a;
	map_second = swap_order ? map_a : map_b;

	map__set_start(map_first, 1000);
	map__set_end(map_first, 1100);
	map__set_start(map_second, 1000);
	map__set_end(map_second, 1200);
	map__set_start(map_keep, 1000);
	map__set_end(map_keep, 1300);

	if (maps__insert(maps, map_first) ||
	    maps__insert(maps, map_second) ||
	    maps__insert(maps, map_keep))
		goto out_maps;

	/* Trigger sorting of maps_by_address, and optionally maps_by_name. */
	found = maps__find(maps, 1000);
	map__zput(found);
	if (use_by_name) {
		found = maps__find_by_name(maps, "z_keep");
		map__zput(found);
	}

	/* Missing map must not wrap around to index 0 in maps__find_next_entry(). */
	found = maps__find_next_entry(maps, missing);
	if (found) {
		map__zput(found);
		goto out_maps;
	}

	if (use_fixup_end) {
		maps__fixup_end(maps);
	} else {
		/*
		 * Simulate in-place end adjustment (as in module map setup),
		 * which can invert the pointer tie-breaker in map__start_cmp().
		 */
		map__set_end(map_second, 1100);
	}

	if (use_remove_maps) {
		map__zput(map_a);
		map__zput(map_b);
		map__zput(map_keep);
		maps__remove_maps(maps, remove_not_keep_cb, (void *)"z_keep");
		if (use_by_name) {
			found = maps__find_by_name(maps, "z_keep");
			if (found && maps__nr_maps(maps) == 1)
				ret = TEST_OK;
			map__zput(found);
		} else {
			ret = check_maps(expected_after_remove_maps,
					 ARRAY_SIZE(expected_after_remove_maps), maps);
		}
	} else {
		maps__remove(maps, map_first);
		map__zput(map_a);
		map__zput(map_b);
		map__zput(map_keep);
		if (use_by_name) {
			found = maps__find_by_name(maps, "z_keep");
			if (found && maps__nr_maps(maps) == 2)
				ret = TEST_OK;
			map__zput(found);
		} else {
			ret = check_maps(expected_after_first,
					 ARRAY_SIZE(expected_after_first), maps);
		}
	}

out_maps:
	map__zput(map_a);
	map__zput(map_b);
	map__zput(map_keep);
	map__zput(missing);
out_env:
	maps__zput(maps);
	machine__delete(machine);
	perf_env__exit(&host_env);
	return ret;
}

static int test__maps__remove(struct test_suite *t __maybe_unused, int subtest __maybe_unused)
{
	for (int fixup = 0; fixup <= 1; fixup++) {
		for (int by_name = 0; by_name <= 1; by_name++) {
			for (int swap = 0; swap <= 1; swap++) {
				TEST_ASSERT_VAL("maps__remove failed",
						check_remove_after_end_update(swap, by_name,
									      fixup, false) ==
						TEST_OK);
				TEST_ASSERT_VAL("maps__remove_maps failed",
						check_remove_after_end_update(swap, by_name,
									      fixup, true) ==
						TEST_OK);
			}
		}
	}
	return TEST_OK;
}

static struct test_case tests__maps[] = {
	TEST_CASE("Test merge_in interface", maps__merge_in),
	TEST_CASE("Test fix up overlap interface", maps__fixup_overlap_and_insert),
	TEST_CASE("Test remove interface", maps__remove),
	{	.name = NULL, }
};

struct test_suite suite__maps = {
	.desc = "Maps - per process mmaps abstraction",
	.test_cases = tests__maps,
};
