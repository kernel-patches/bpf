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

#include <userapi.h>
#include <selftest_helpers.h>

#include "selftest.h"

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

static bool verbose = false;
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

int run_test(selftest *skel, const struct bpf_program *prog)
{
	size_t arena_pages = (1UL << 32) / sysconf(_SC_PAGESIZE);
	int prog_fd;
	int ret;

	ret = libarena_run_prog(bpf_program__fd(skel->progs.arena_alloc_reserve));
	if (ret)
		return ret;

#ifdef BPF_ARENA_ASAN
	ret = libarena_asan_init(
		bpf_program__fd(skel->progs.arena_get_base),
		bpf_program__fd(skel->progs.asan_init),
		arena_pages);
	if (ret)
		return ret;
#endif

	prog_fd = bpf_program__fd(prog);
	if (prog_fd < 0)
		return prog_fd;

	return run_prog_verbose(prog_fd);
}

#define TEST(__test)					\
int run_##__test(void)					\
{							\
	selftest *skel;					\
	int ret;					\
							\
	skel = selftest__open_and_load();		\
	if (!skel) {					\
		ret = -EINVAL;				\
		goto error_no_destroy;			\
	}						\
							\
	ret = selftest__attach(skel);			\
	if (ret)					\
		goto error;				\
							\
	ret = run_test(skel, skel->progs.__test);	\
	if (ret)					\
		goto error;				\
							\
	selftest__destroy(skel);			\
							\
	printf("ok %d - %s\n", testno++, #__test);	\
	return 0;					\
							\
error:							\
	selftest__destroy(skel);			\
error_no_destroy:					\
	printf("not ok %d - %s\n", testno++, #__test);	\
	return ret;					\
}

TEST(test_buddy);

#ifdef BPF_ARENA_ASAN
TEST(asan_test_buddy);
#endif

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
	int ret;

	struct rlimit rlim = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	banner(argv[0]);

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0)
			verbose = true;
	}

	ret = setrlimit(RLIMIT_MEMLOCK, &rlim);
	if (ret) {
		perror("setrlimit");
		return ret;
	}

	libbpf_set_print(libbpf_print_fn);

	run_test_buddy();

#ifdef BPF_ARENA_ASAN
	run_asan_test_buddy();
#endif

	return 0;
}
