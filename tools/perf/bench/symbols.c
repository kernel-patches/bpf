// SPDX-License-Identifier: GPL-2.0
/*
 * Benchmark symbol loading, sorting, and address/name lookup.
 */
#include <elf.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <linux/compiler.h>
#include <linux/kernel.h>
#include <linux/time64.h>
#include <subcmd/parse-options.h>
#include "bench.h"
#include "../util/debug.h"
#include "../util/dso.h"
#include "../util/map.h"
#include "../util/stat.h"
#include "../util/symbol.h"
#include "../util/util.h"

static unsigned int iterations = 20;
static unsigned int nr_symbols = 10000;
static unsigned int nr_appends = 200;
static const char *binary_path;
static bool no_demangle;

static const struct option options[] = {
	OPT_UINTEGER('i', "iterations", &iterations,
		     "Number of iterations used to compute average (default: 20)"),
	OPT_STRING('b', "binary", &binary_path, "path",
		   "Binary path for ELF symbol load benchmark (default: perf binary)"),
	OPT_UINTEGER('n', "nr-symbols", &nr_symbols,
		     "Number of synthetic symbols for bulk benchmark (default: 10000)"),
	OPT_UINTEGER('a', "nr-appends", &nr_appends,
		     "Number of incremental symbol appends per iteration (default: 200)"),
	OPT_BOOLEAN(0, "no-demangle", &no_demangle,
		    "Disable symbol demangling during ELF load"),
	OPT_END()
};

static const char *const bench_usage[] = {
	"perf bench internals symbols <options>",
	NULL
};

static int do_dso_load_bench(const char *path, bool *skipped)
{
	struct stats time_stats;
	struct rusage rusage;
	unsigned int i;

	*skipped = false;
	init_stats(&time_stats);

	for (i = 0; i < iterations; i++) {
		struct timeval start, end, diff;
		struct map *map;
		struct dso *dso;
		u64 runtime_us;
		int nr;

		gettimeofday(&start, NULL);
		map = dso__new_map(path);
		if (!map) {
			pr_err("Failed to create map for %s\n", path);
			return -ENOMEM;
		}
		dso = map__dso(map);
		nr = dso__load(dso, map);
		if (nr < 0) {
			pr_err("Failed to load symbols from %s\n", path);
			map__put(map);
			return -EINVAL;
		}
		if (nr == 0) {
			printf("  Skipping DSO load benchmark (%s has no symbols)\n", path);
			map__put(map);
			*skipped = true;
			return 0;
		}
		gettimeofday(&end, NULL);

		map__put(map);

		timersub(&end, &start, &diff);
		runtime_us = (u64)diff.tv_sec * USEC_PER_SEC + diff.tv_usec;
		update_stats(&time_stats, runtime_us);
	}

	printf("  Average DSO load: %.3f msec (+- %.3f msec)\n",
	       avg_stats(&time_stats) / USEC_PER_MSEC,
	       stddev_stats(&time_stats) / USEC_PER_MSEC);
	if (getrusage(RUSAGE_SELF, &rusage) == 0)
		printf("  Max RSS (DSO load): %ld KB\n", rusage.ru_maxrss);
	return 0;
}

static int do_dso_sort_by_name_bench(const char *path)
{
	struct stats time_stats;
	struct rusage rusage;
	unsigned int i;

	init_stats(&time_stats);

	for (i = 0; i < iterations; i++) {
		struct timeval start, end, diff;
		struct map *map;
		struct dso *dso;
		u64 runtime_us;

		map = dso__new_map(path);
		if (!map) {
			pr_err("Failed to create map for %s\n", path);
			return -ENOMEM;
		}
		dso = map__dso(map);
		if (dso__load(dso, map) <= 0) {
			map__put(map);
			return -EINVAL;
		}

		gettimeofday(&start, NULL);
		dso__sort_by_name(dso);
		gettimeofday(&end, NULL);

		map__put(map);

		timersub(&end, &start, &diff);
		runtime_us = (u64)diff.tv_sec * USEC_PER_SEC + diff.tv_usec;
		update_stats(&time_stats, runtime_us);
	}

	printf("  Average DSO sort by name: %.3f msec (+- %.3f msec)\n",
	       avg_stats(&time_stats) / USEC_PER_MSEC,
	       stddev_stats(&time_stats) / USEC_PER_MSEC);
	if (getrusage(RUSAGE_SELF, &rusage) == 0)
		printf("  Max RSS (with sort by name): %ld KB\n", rusage.ru_maxrss);
	return 0;
}

static int do_synthetic_symbols_bench(void)
{
	struct stats bulk_stats, append_stats;
	unsigned int i, j, half = nr_symbols / 2;

	if (half == 0)
		return 0;

	init_stats(&bulk_stats);
	init_stats(&append_stats);

	for (i = 0; i < iterations; i++) {
		struct timeval start, end, diff;
		struct dso *dso = dso__new("[bench_symbols]");
		u64 runtime_us;
		char name[32];

		if (!dso)
			return -ENOMEM;

		/*
		 * Phase 1: Insert symbols in two ascending runs (simulating
		 * .symtab + .dynsym), fixup ends and duplicates, and look up
		 * all symbols by address.
		 */
		gettimeofday(&start, NULL);
		for (j = 0; j < nr_symbols; j++) {
			u64 addr = (j < half) ?
				(0x100000ULL + (u64)j * 0x40ULL) :
				(0x100020ULL + (u64)(j - half) * 0x40ULL);
			struct symbol *sym;

			scnprintf(name, sizeof(name), "bench_sym_%06u", j);
			sym = symbol__new(addr, 0x18, STB_GLOBAL, STT_FUNC, name);
			if (!sym) {
				dso__put(dso);
				return -ENOMEM;
			}
			symbols__insert(dso__symbols(dso), sym);
		}
		symbols__fixup_end(dso__symbols(dso), false);
		symbols__fixup_duplicate(dso__symbols(dso));

		for (j = 0; j < nr_symbols; j++) {
			u64 addr = (j < half) ?
				(0x100000ULL + (u64)j * 0x40ULL + 4) :
				(0x100020ULL + (u64)(j - half) * 0x40ULL + 4);

			(void)dso__find_symbol_nocache(dso, addr);
		}
		gettimeofday(&end, NULL);
		timersub(&end, &start, &diff);
		runtime_us = (u64)diff.tv_sec * USEC_PER_SEC + diff.tv_usec;
		update_stats(&bulk_stats, runtime_us);

		/*
		 * Phase 2: Incrementally append one symbol at a time at an
		 * interior address and immediately query by address.
		 */
		gettimeofday(&start, NULL);
		for (j = 0; j < nr_appends; j++) {
			u64 addr = 0x100010ULL + ((u64)(j * 197 % half)) * 0x40ULL;
			struct symbol *sym;

			scnprintf(name, sizeof(name), "jit_sym_%06u", j);
			sym = symbol__new(addr, 0x08, STB_GLOBAL, STT_FUNC, name);
			if (!sym) {
				dso__put(dso);
				return -ENOMEM;
			}
			dso__insert_symbol(dso, sym);
			(void)dso__find_symbol_nocache(dso, addr + 2);
		}
		gettimeofday(&end, NULL);
		timersub(&end, &start, &diff);
		runtime_us = (u64)diff.tv_sec * USEC_PER_SEC + diff.tv_usec;
		update_stats(&append_stats, runtime_us);

		dso__put(dso);
	}

	printf("  Average bulk insert + lookup: %.3f usec (+- %.3f usec)\n",
	       avg_stats(&bulk_stats), stddev_stats(&bulk_stats));
	printf("  Average append + lookup: %.3f usec (+- %.3f usec)\n",
	       avg_stats(&append_stats), stddev_stats(&append_stats));
	return 0;
}

int bench_symbols(int argc, const char **argv)
{
	char exe_buf[PATH_MAX];
	const char *path;
	bool orig_demangle;
	bool skipped = false;
	int err;

	argc = parse_options(argc, argv, options, bench_usage, 0);
	if (argc) {
		usage_with_options(bench_usage, options);
		exit(EXIT_FAILURE);
	}

	if (symbol__init(NULL) < 0)
		return -1;

	orig_demangle = symbol_conf.demangle;
	if (no_demangle)
		symbol_conf.demangle = false;

	if (binary_path) {
		path = binary_path;
	} else {
		perf_exe(exe_buf, sizeof(exe_buf));
		path = exe_buf;
	}

	err = do_dso_load_bench(path, &skipped);
	if (!err && !skipped)
		err = do_dso_sort_by_name_bench(path);
	if (!err)
		err = do_synthetic_symbols_bench();

	symbol_conf.demangle = orig_demangle;
	symbol__exit();
	return err;
}
