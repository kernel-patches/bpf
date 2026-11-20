// SPDX-License-Identifier: GPL-2.0
/*
 * Benchmark maps insertion, sorting, and address/name lookup.
 */
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <linux/compiler.h>
#include <linux/kernel.h>
#include <linux/time64.h>
#include <subcmd/parse-options.h>
#include "bench.h"
#include "../util/debug.h"
#include "../util/dso.h"
#include "../util/env.h"
#include "../util/machine.h"
#include "../util/map.h"
#include "../util/maps.h"
#include "../util/stat.h"

static unsigned int iterations = 100;
static unsigned int nr_maps = 1000;
static unsigned int nr_appends = 200;

static const struct option options[] = {
	OPT_UINTEGER('i', "iterations", &iterations,
		     "Number of iterations used to compute average (default: 100)"),
	OPT_UINTEGER('m', "nr-maps", &nr_maps,
		     "Number of ascending maps per iteration (default: 1000)"),
	OPT_UINTEGER('a', "nr-appends", &nr_appends,
		     "Number of incremental map appends per iteration (default: 200)"),
	OPT_END()
};

static const char *const bench_usage[] = {
	"perf bench internals maps <options>",
	NULL
};

static int do_maps_bench(void)
{
	struct stats asc_stats, append_stats;
	unsigned int total_dsos = nr_maps + nr_appends;
	struct perf_env host_env;
	struct machine *machine;
	struct dso **dsos;
	struct map **all_maps;
	unsigned int i, j;
	int err = 0;

	if (total_dsos == 0)
		return 0;

	perf_env__init(&host_env);
	machine = machine__new_live(&host_env, /*kernel_maps=*/false, getpid());
	if (!machine) {
		perf_env__exit(&host_env);
		return -ENOMEM;
	}

	dsos = calloc(total_dsos, sizeof(*dsos));
	all_maps = calloc(total_dsos, sizeof(*all_maps));
	if (!dsos || !all_maps) {
		free(dsos);
		free(all_maps);
		machine__delete(machine);
		perf_env__exit(&host_env);
		return -ENOMEM;
	}

	for (i = 0; i < total_dsos; i++) {
		char name[32];
		u64 addr;

		scnprintf(name, sizeof(name), "/tmp/bench_dso_%06u.so", i);
		dsos[i] = dso__new(name);
		if (!dsos[i]) {
			err = -ENOMEM;
			goto out_free;
		}
		if (i < nr_maps) {
			addr = 0x100000ULL + (u64)i * 0x2000ULL;
			all_maps[i] = map__new2(addr, dsos[i]);
			if (!all_maps[i]) {
				err = -ENOMEM;
				goto out_free;
			}
			map__set_end(all_maps[i], addr + 0x1000ULL);
		} else {
			u64 k = i - nr_maps;
			u64 slot = nr_maps ? (k * 197ULL) % nr_maps : k;

			addr = 0x101000ULL + slot * 0x2000ULL +
			       (nr_maps ? (k / nr_maps) * 0x100ULL : 0);
			all_maps[i] = map__new2(addr, dsos[i]);
			if (!all_maps[i]) {
				err = -ENOMEM;
				goto out_free;
			}
			map__set_end(all_maps[i], addr + 0x80ULL);
		}
	}

	init_stats(&asc_stats);
	init_stats(&append_stats);

	for (i = 0; i < iterations; i++) {
		struct timeval start, end, diff;
		struct maps *maps = maps__new(machine);
		u64 runtime_us;

		if (!maps) {
			err = -ENOMEM;
			goto out_free;
		}

		/*
		 * Phase 1: Insert maps in ascending address order (simulating
		 * /proc/<pid>/maps synthesis) and look up each map by address.
		 */
		gettimeofday(&start, NULL);
		for (j = 0; j < nr_maps; j++) {
			err = maps__fixup_overlap_and_insert(maps, all_maps[j]);
			if (err) {
				maps__zput(maps);
				goto out_free;
			}
		}
		for (j = 0; j < nr_maps; j++) {
			u64 addr = 0x100000ULL + (u64)j * 0x2000ULL + 0x100ULL;
			struct map *found = maps__find(maps, addr);

			map__put(found);
		}
		gettimeofday(&end, NULL);
		timersub(&end, &start, &diff);
		runtime_us = diff.tv_sec * USEC_PER_SEC + diff.tv_usec;
		update_stats(&asc_stats, runtime_us);

		/*
		 * Phase 2: Incrementally insert maps at interior addresses
		 * (simulating runtime MMAP2 / JIT code events) and immediately
		 * query by address and by name.
		 */
		gettimeofday(&start, NULL);
		for (j = 0; j < nr_appends; j++) {
			struct map *map = all_maps[nr_maps + j];
			struct dso *dso = dsos[nr_maps + j];
			u64 addr = map__start(map);
			struct map *found;

			err = maps__fixup_overlap_and_insert(maps, map);
			if (err) {
				maps__zput(maps);
				goto out_free;
			}

			found = maps__find(maps, addr + 0x10ULL);
			map__put(found);

			found = maps__find_by_name(maps, dso__short_name(dso));
			map__put(found);
		}
		gettimeofday(&end, NULL);
		timersub(&end, &start, &diff);
		runtime_us = diff.tv_sec * USEC_PER_SEC + diff.tv_usec;
		update_stats(&append_stats, runtime_us);

		maps__zput(maps);
	}

	printf("  Average ascending insert + lookup: %.3f usec (+- %.3f usec)\n",
	       avg_stats(&asc_stats), stddev_stats(&asc_stats));
	printf("  Average append + lookup: %.3f usec (+- %.3f usec)\n",
	       avg_stats(&append_stats), stddev_stats(&append_stats));

out_free:
	for (i = 0; i < total_dsos; i++) {
		map__put(all_maps[i]);
		dso__put(dsos[i]);
	}
	free(all_maps);
	free(dsos);
	machine__delete(machine);
	perf_env__exit(&host_env);
	return err;
}

int bench_maps(int argc, const char **argv)
{
	argc = parse_options(argc, argv, options, bench_usage, 0);
	if (argc) {
		usage_with_options(bench_usage, options);
		exit(EXIT_FAILURE);
	}

	return do_maps_bench();
}
