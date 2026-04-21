// SPDX-License-Identifier: LGPL-2.1 OR BSD-2-Clause
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>

#include <common.h>
#include <asan.h>
#include <selftest_helpers.h>

#ifdef BPF_ARENA_ASAN
#include "../libarena_asan.skel.h"
typedef struct libarena_asan selftest;
#define selftest__open libarena_asan__open
#define selftest__open_and_load libarena_asan__open_and_load
#define selftest__load libarena_asan__load
#define selftest__attach libarena_asan__attach
#define selftest__destroy libarena_asan__destroy
#else
#include "../libarena.skel.h"
typedef struct libarena selftest;
#define selftest__open libarena__open
#define selftest__open_and_load libarena__open_and_load
#define selftest__load libarena__load
#define selftest__attach libarena__attach
#define selftest__destroy libarena__destroy
#endif

static bool verbose;
static int testno = 1;

static int
run_prog_verbose(int prog_fd)
{
	char buf[1024];
	int ret, err;

	ret = libarena_run_prog(prog_fd);

	if (ret)
		fprintf(stderr, "error %d in %s\n", ret, __func__);

	if (verbose) {
		printf("BPF stdout:\n");
		while ((err = bpf_prog_stream_read(prog_fd, 1, buf, 1024, NULL)) > 0)
			printf("%.*s", err, buf);

		if (err)
			return err;

		printf("BPF stderr:\n");
		while ((err = bpf_prog_stream_read(prog_fd, 2, buf, 1024, NULL)) > 0)
			printf("%.*s", err, buf);

		if (err)
			return err;
	}

	return ret;
}

static int libbpf_print_fn(enum libbpf_print_level level,
		const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

static int init_arena(selftest *skel)
{
	int ret;

	ret = libarena_run_prog(bpf_program__fd(skel->progs.arena_alloc_reserve));
	if (ret)
		return ret;

#ifdef BPF_ARENA_ASAN
	ret = libarena_asan_init(
		bpf_program__fd(skel->progs.arena_get_base),
		bpf_program__fd(skel->progs.asan_init),
		(1ULL << 32) / sysconf(_SC_PAGESIZE));
	if (ret)
		return ret;
#endif

	return 0;
}

static int run_test(selftest *skel, struct bpf_program *prog)
{
	int prog_fd;

	prog_fd = bpf_program__fd(prog);
	if (prog_fd < 0)
		return prog_fd;

	return run_prog_verbose(prog_fd);
}

static void
banner(const char *progpath)
{
	char *name = basename(progpath);
	bool is_asan;

	/* Check if our BPF programs are ASAN-capable using strstr on the prog name. */
	printf("%s\n", name);
	is_asan = strstr(name, "_asan");

	printf("=== %s %s===\n", "libarena selftests", is_asan ? "(asan) " : "");
}

int main(int argc, char *argv[])
{
	struct bpf_program *prog;
	selftest *skel;
	int err = 0;
	int ret;

	banner(argv[0]);

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
			verbose = true;
			continue;
		}

		fprintf(stderr, "usage: ./%s [-v] [--verbose]\n", argv[0]);
		fprintf(stderr, "verbose option prints out BPF streams,"
				" including ASAN stacks when applicable\n");

		return -EINVAL;
	}

	libbpf_set_print(libbpf_print_fn);

	skel = selftest__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load skeleton\n");
		return 1;
	}

	ret = selftest__attach(skel);
	if (ret) {
		fprintf(stderr, "Failed to attach skeleton\n");
		selftest__destroy(skel);
		return 1;
	}

	ret = init_arena(skel);
	if (ret) {
		fprintf(stderr, "Failed to initialize arena: %d\n", ret);
		selftest__destroy(skel);
		return 1;
	}

	bpf_object__for_each_program(prog, skel->obj) {
		const char *name = bpf_program__name(prog);

		if (!libarena_is_test_prog(name) && !libarena_is_asan_test_prog(name))
			continue;

		ret = run_test(skel, prog);
		if (ret)
			printf("not ok %d - %s\n", testno++, name);
		else
			printf("ok %d - %s\n", testno++, name);

		if (ret)
			err = -EINVAL;
	}

	selftest__destroy(skel);

	return err;
}
