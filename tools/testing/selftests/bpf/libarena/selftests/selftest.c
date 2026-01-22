/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>

#include <userapi.h>

#include "selftest.h"

#include "../selftest.skel.h"
typedef struct selftest selftest;

static bool verbose = false;
static int testno = 1;

typedef int (*selftest_func)(selftest *);

static int
selftest_fd(int prog_fd, struct bpf_test_run_opts *calleropts)
{
	struct bpf_test_run_opts opts, *argopts;
	char buf[1024];
	int progret;
	int ret;

	argopts = calleropts;
	if (!argopts) {
		memset(&opts, 0, sizeof(opts));
		opts.sz = sizeof(opts);
		argopts = &opts;
	}

	ret = bpf_prog_test_run_opts(prog_fd, argopts);
	if (ret)
		return ret;

	if (argopts->retval)
		fprintf(stderr, "error %d in %s\n", argopts->retval, __func__);

	if (verbose) {
	printf("BPF stdout:\n");
		while ((ret = bpf_prog_stream_read(prog_fd, 1, buf, 1024, NULL)) > 0)
			printf("%.*s", ret, buf);

		if (ret)
			return ret;

		printf("BPF stderr:\n");
		while ((ret = bpf_prog_stream_read(prog_fd, 2, buf, 1024, NULL)) > 0)
			printf("%.*s", ret, buf);
	}

	return 0;
}

static int
selftest_arena_alloc_reserve(selftest *skel)
{
	int prog_fd;
	int ret;

	prog_fd = bpf_program__fd(skel->progs.arena_alloc_reserve);
	if (!prog_fd)
		return -ENOENT;

	return selftest_fd(prog_fd, NULL);
}

static int
selftest_arena_base(selftest *skel, void **arena_base)
{
	struct bpf_test_run_opts opts;
	struct arena_get_base_args args;
	u64 globals_pages;
	int prog_fd;
	int ret;

	args = (struct arena_get_base_args) {
		.arena_base = NULL
	};

	opts = (struct bpf_test_run_opts) {
		.sz = sizeof(opts),
		.ctx_in = &args,
		.ctx_size_in = sizeof(args),
	};

	prog_fd = bpf_program__fd(skel->progs.arena_get_base);
	assert(prog_fd >= 0 && "no program found");

	ret = selftest_fd(prog_fd, &opts);
	if (ret)
		return ret;

	*arena_base = args.arena_base;

	return 0;
}

static int
selftest_globals_pages(selftest *skel, size_t arena_all_pages, u64 *globals_pages)
{
	size_t pgsize = sysconf(_SC_PAGESIZE);
	void *arena_base;
	u64 pages;
	u8 *vec;
	int ret;
	int i;

	ret = selftest_arena_base(skel, &arena_base);
	if (ret)
		return ret;

	if (!arena_base)
		return -EINVAL;

	vec = calloc(arena_all_pages, sizeof(*vec));
	if (!vec)
		return -ENOMEM;

	if (mincore(arena_base, arena_all_pages * pgsize, vec)) {
		perror("mincore");
		free(vec);
		return -1;
	}

	/* Find the first nonresident page. */
	pages = 0;
	for (i = arena_all_pages - 1; i >= 0; i--) {
		if (!(vec[i] & 0x1))
			break;

		pages += 1;
	}

	free(vec);

	*globals_pages = pages;

	return 0;
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
	int prog_fd;
	int ret;

	ret = selftest_arena_alloc_reserve(skel);
	if (ret)
		return ret;

	prog_fd = bpf_program__fd(prog);
	if (!prog_fd)
		return -ENOENT;

	return selftest_fd(prog_fd, NULL);
}

#define TEST(__test)					\
int run_##__test(void)					\
{							\
	selftest *skel;					\
	int ret;					\
							\
	skel = selftest__open_and_load();		\
	if (!skel)					\
		goto error;				\
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
	printf("not ok %d - %s\n", testno++, #__test);	\
	return ret;					\
}

static void
banner(const char *progpath)
{
	char *name = basename(progpath);

	printf("=== %s ===\n", "libarena selftests");
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

	return 0;
}
