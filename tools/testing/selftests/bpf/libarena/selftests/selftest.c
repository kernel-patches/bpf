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

#include <asan.h>

#ifdef BPF_ARENA_ASAN
#include "../selftest_asan.skel.h"
typedef struct selftest_asan selftest;
#define selftest__open selftest_asan__open
#define selftest__open_and_load selftest_asan__open_and_load
#define selftest__load selftest_asan__load
#define selftest__attach selftest_asan__attach
#define selftest__destroy selftest_asan__destroy
#else
#include "../selftest.skel.h"
typedef struct selftest selftest;
#endif

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

#if BPF_ARENA_ASAN
static int
selftest_asan_init(selftest *skel)
{
	struct bpf_test_run_opts opts;
	size_t arena_all_pages = 1ULL << 20;
	struct asan_init_args args;
	u64 globals_pages;
	int prog_fd;
	int ret;

	ret = selftest_globals_pages(skel, arena_all_pages, &globals_pages);
	if (ret)
		return ret;

	/* Taken from the arena map header. */
	args = (struct asan_init_args) {
		.arena_all_pages = arena_all_pages,
		.arena_globals_pages = globals_pages,
	};

	opts = (struct bpf_test_run_opts) {
		.sz = sizeof(opts),
		.ctx_in = &args,
		.ctx_size_in = sizeof(args),
	};

	prog_fd = bpf_program__fd(skel->progs.asan_init);
	assert(prog_fd >= 0 && "no program found");
	return selftest_fd(prog_fd, &opts);
}

#else /* BPF_ARENA_ASAN */

static int
selftest_asan_init(selftest *skel)
{
	return 0;
}

#endif /* BPF_ARENA_ASAN */

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

	ret = selftest_asan_init(skel);
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

TEST(bump_selftest);
TEST(buddy_selftest);

#ifdef BPF_ARENA_ASAN
TEST(asan_test_bump);
TEST(asan_test_stack);
TEST(asan_test_buddy);
#endif

static void
banner(const char *progpath)
{
	char *name = basename(progpath);
	bool is_asan;

	/* 
	 * Check if our BPF programs are ASAN-capable by inspecting the prog name.
	 * Command line arguments are guaranteed to be NULL-terminated, use strlen. 
	 * Calculate the hardcoded name's length at compile time.
	 */
	printf("%s\n", name);
	is_asan = strlen(name) > (sizeof("selftest") - 1);

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

	run_bump_selftest();
	run_buddy_selftest();

#ifdef BPF_ARENA_ASAN
	run_asan_test_bump();
	run_asan_test_stack();
	run_asan_test_buddy();
#endif

	return 0;
}
