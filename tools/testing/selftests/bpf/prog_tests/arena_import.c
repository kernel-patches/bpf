// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 NVIDIA Corporation */

#include <test_progs.h>
#include <fcntl.h>
#include <signal.h>
#include <stdatomic.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include "arena_import.skel.h"

#define MEMFD_PAGES	4

#ifndef F_SEAL_FUTURE_WRITE
#define F_SEAL_FUTURE_WRITE	0x0010
#endif

static long ps;

static int run(struct bpf_program *prog)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int err;

	err = bpf_prog_test_run_opts(bpf_program__fd(prog), &opts);
	if (!ASSERT_OK(err, bpf_program__name(prog)))
		return -1;
	return opts.retval;
}

static int do_import(struct arena_import *skel, int fd, long fd_off, __u32 pg, __u32 cnt)
{
	skel->bss->fd = fd;
	skel->bss->fd_off = fd_off;
	skel->bss->pg = pg;
	skel->bss->page_cnt = cnt;
	skel->bss->ret = 1;
	if (run(skel->progs.op_import))
		return 1;
	return skel->bss->ret;
}

static int do_import_dax(struct arena_import *skel, void *src, __u32 pg, __u32 cnt)
{
	skel->bss->src = (unsigned long)src;
	skel->bss->pg = pg;
	skel->bss->page_cnt = cnt;
	skel->bss->ret = 1;
	if (run(skel->progs.op_import_dax))
		return 1;
	return skel->bss->ret;
}

static int do_alloc(struct arena_import *skel, __u32 pg, __u32 cnt)
{
	skel->bss->pg = pg;
	skel->bss->page_cnt = cnt;
	skel->bss->ret = 1;
	if (run(skel->progs.op_alloc))
		return 1;
	return skel->bss->ret;
}

static void do_free(struct arena_import *skel, __u32 pg, __u32 cnt)
{
	skel->bss->pg = pg;
	skel->bss->page_cnt = cnt;
	run(skel->progs.op_free);
}

static void do_write(struct arena_import *skel, __u32 pg, __u64 val)
{
	skel->bss->pg = pg;
	skel->bss->val = val;
	run(skel->progs.op_write);
}

static __u64 do_read(struct arena_import *skel, __u32 pg)
{
	skel->bss->pg = pg;
	skel->bss->val = 0;
	run(skel->progs.op_read);
	return skel->bss->val;
}

static int make_memfd(unsigned int seals)
{
	int fd;

	fd = memfd_create("arena_import", MFD_ALLOW_SEALING);
	if (fd < 0 && errno == ENOSYS) {
		printf("%s:SKIP:no memfd_create()\n", __func__);
		test__skip();
		return -1;
	}
	if (!ASSERT_OK_FD(fd, "memfd_create"))
		return -1;
	if (!ASSERT_OK(ftruncate(fd, MEMFD_PAGES * ps), "ftruncate"))
		goto err;
	if (seals && !ASSERT_OK(fcntl(fd, F_ADD_SEALS, seals), "add_seals"))
		goto err;
	return fd;
err:
	close(fd);
	return -1;
}

static struct arena_import *open_skel(void)
{
	struct arena_import *skel;
	size_t sz;

	skel = arena_import__open_and_load();
	if (!skel && errno == EOPNOTSUPP) {
		printf("%s:SKIP:no arena support\n", __func__);
		test__skip();
		return NULL;
	}
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return NULL;
	if (skel->rodata->skip) {
		printf("%s:SKIP:the compiler lacks arena address space casts\n", __func__);
		test__skip();
		arena_import__destroy(skel);
		return NULL;
	}
	skel->bss->base = bpf_map__initial_value(skel->maps.arena, &sz);
	if (!ASSERT_OK_PTR(skel->bss->base, "arena_base")) {
		arena_import__destroy(skel);
		return NULL;
	}
	skel->bss->page_size = ps;
	return skel;
}

/* Imported pages are not allocated by the arena and must not be counted */
static long map_memlock(int map_fd)
{
	char path[64], line[128];
	long memlock = -1;
	FILE *f;

	snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", map_fd);
	f = fopen(path, "r");
	if (!ASSERT_OK_PTR(f, "open_fdinfo"))
		return -1;
	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "memlock:\t%ld", &memlock) == 1)
			break;
	}
	fclose(f);
	return memlock;
}

/* Data written on either side is visible on the other one */
static void test_share(void)
{
	struct arena_import *skel;
	__u64 *shm = MAP_FAILED;
	__u64 val;
	int fd, i;

	fd = make_memfd(F_SEAL_SHRINK);
	if (fd < 0)
		return;
	skel = open_skel();
	if (!skel)
		goto out;

	/* Import memfd pages 1-2 at test pages 2-3, see page_addr() */
	if (!ASSERT_OK(do_import(skel, fd, ps, 2, 2), "import"))
		goto out;
	ASSERT_EQ(map_memlock(bpf_map__fd(skel->maps.arena)), 0, "memlock");

	shm = mmap(NULL, MEMFD_PAGES * ps, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (!ASSERT_NEQ(shm, MAP_FAILED, "mmap_memfd"))
		goto out;

	do_write(skel, 2, 0xcafe);
	do_write(skel, 3, 0xbeef);
	ASSERT_EQ(shm[ps / sizeof(*shm)], 0xcafe, "bpf_to_user_pg2");
	ASSERT_EQ(shm[2 * ps / sizeof(*shm)], 0xbeef, "bpf_to_user_pg3");

	shm[ps / sizeof(*shm)] = 0xf00d;
	ASSERT_EQ(do_read(skel, 2), 0xf00d, "user_to_bpf");

	/* Pages outside of the imported range are not shared */
	if (!ASSERT_OK(do_alloc(skel, 0, 1), "alloc"))
		goto out;
	do_write(skel, 0, 0xdead);
	ASSERT_EQ(do_read(skel, 0), 0xdead, "allocated");
	ASSERT_EQ(shm[0], 0, "not_shared");

	/*
	 * The data outlives the arena. The arena releases the pages after an
	 * RCU grace period: sealing the memfd against writes fails while they
	 * are pinned, so wait until it works (no writable mapping either).
	 */
	arena_import__destroy(skel);
	skel = NULL;
	munmap(shm, MEMFD_PAGES * ps);
	shm = MAP_FAILED;
	for (i = 0; i < 500 && fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE); i++)
		usleep(10000);
	if (ASSERT_LT(i, 500, "released") &&
	    ASSERT_EQ(pread(fd, &val, sizeof(val), 2 * ps), sizeof(val), "pread"))
		ASSERT_EQ(val, 0xbeef, "after_destroy");
out:
	if (shm != MAP_FAILED)
		munmap(shm, MEMFD_PAGES * ps);
	arena_import__destroy(skel);
	close(fd);
}

/* Freeing any imported page releases the whole import, the data stays in the memfd */
static void test_free(void)
{
	struct arena_import *skel;
	__u64 *shm = MAP_FAILED;
	int fd;

	fd = make_memfd(F_SEAL_SHRINK);
	if (fd < 0)
		return;
	skel = open_skel();
	if (!skel)
		goto out;

	shm = mmap(NULL, MEMFD_PAGES * ps, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (!ASSERT_NEQ(shm, MAP_FAILED, "mmap_memfd"))
		goto out;

	/* Allocated page 0, memfd pages 0-1 imported at 1-2, allocated page 3 */
	if (!ASSERT_OK(do_alloc(skel, 0, 1), "alloc_pg0") ||
	    !ASSERT_OK(do_import(skel, fd, 0, 1, 2), "import") ||
	    !ASSERT_OK(do_alloc(skel, 3, 1), "alloc_pg3"))
		goto out;
	do_write(skel, 0, 0x1);
	do_write(skel, 1, 0x1234);
	do_write(skel, 2, 0x5678);
	do_write(skel, 3, 0x3);

	/* Page 2 only: pages 1-2 go away, 0 and 3 stay */
	do_free(skel, 2, 1);
	ASSERT_EQ(do_read(skel, 1), 0, "pg1_unmapped");
	ASSERT_EQ(do_read(skel, 2), 0, "pg2_unmapped");
	ASSERT_EQ(do_read(skel, 0), 0x1, "pg0_kept");
	ASSERT_EQ(do_read(skel, 3), 0x3, "pg3_kept");
	ASSERT_EQ(shm[0], 0x1234, "memfd_kept");

	/* The range can be imported again */
	if (!ASSERT_OK(do_import(skel, fd, 0, 1, 2), "reimport"))
		goto out;
	ASSERT_EQ(do_read(skel, 2), 0x5678, "reimported");

	/* Across allocated and imported pages, then the whole arena is free */
	do_free(skel, 0, 4);
	ASSERT_EQ(map_memlock(bpf_map__fd(skel->maps.arena)), 0, "memlock");
	ASSERT_OK(do_alloc(skel, 0, 8), "alloc_all");
out:
	if (shm != MAP_FAILED)
		munmap(shm, MEMFD_PAGES * ps);
	arena_import__destroy(skel);
	close(fd);
}

static void test_invalid(void)
{
	int fd, ro_fd = -1, wo_fd = -1, null_fd = -1;
	struct arena_import *skel;
	char path[64];

	skel = open_skel();
	if (!skel)
		return;

	/* Write seals are not allowed */
	fd = make_memfd(F_SEAL_SHRINK | F_SEAL_FUTURE_WRITE);
	if (fd >= 0) {
		ASSERT_EQ(do_import(skel, fd, 0, 0, 1), -EPERM, "write_seal");
		close(fd);
	}

	fd = make_memfd(F_SEAL_SHRINK);
	if (fd < 0)
		goto out;

	/* The memfd must be open for reading and writing, like for a shared mapping */
	snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
	ro_fd = open(path, O_RDONLY);
	if (ASSERT_OK_FD(ro_fd, "open_ro"))
		ASSERT_EQ(do_import(skel, ro_fd, 0, 0, 1), -EPERM, "read_only");
	wo_fd = open(path, O_WRONLY);
	if (ASSERT_OK_FD(wo_fd, "open_wo"))
		ASSERT_EQ(do_import(skel, wo_fd, 0, 0, 1), -EPERM, "write_only");

	/* Not a memfd */
	null_fd = open("/dev/null", O_RDWR);
	if (ASSERT_OK_FD(null_fd, "open_null"))
		ASSERT_EQ(do_import(skel, null_fd, 0, 0, 1), -EINVAL, "not_memfd");

	ASSERT_EQ(do_import(skel, -1, 0, 0, 1), -EBADF, "bad_fd");
	ASSERT_EQ(do_import(skel, fd, 1, 0, 1), -EINVAL, "unaligned_off");
	ASSERT_EQ(do_import(skel, fd, 0, 0, MEMFD_PAGES + 1), -EINVAL, "beyond_memfd");
	ASSERT_EQ(do_import(skel, fd, 0, 7, 2), -EINVAL, "beyond_arena");
	ASSERT_EQ(do_import(skel, fd, 0, 0, 0), -EINVAL, "zero_pages");

	/* The range must be free */
	if (ASSERT_OK(do_alloc(skel, 0, 1), "alloc"))
		ASSERT_EQ(do_import(skel, fd, 0, 0, 2), -EBUSY, "over_allocated");
	if (ASSERT_OK(do_import(skel, fd, 0, 2, 2), "import"))
		ASSERT_EQ(do_import(skel, fd, 0, 3, 1), -EBUSY, "over_imported");
	do_free(skel, 0, 4);

	/* Nothing above may leave a range behind */
	ASSERT_OK(do_alloc(skel, 0, 8), "alloc_all");
out:
	if (null_fd >= 0)
		close(null_fd);
	if (ro_fd >= 0)
		close(ro_fd);
	if (wo_fd >= 0)
		close(wo_fd);
	if (fd >= 0)
		close(fd);
	arena_import__destroy(skel);
}

static char *fault_expected;

static void fault_handler(int sig, siginfo_t *si, void *uc)
{
	_exit(si->si_addr == fault_expected ? 3 : 4);
}

/* User space accesses imported pages through the memfd, not through the arena */
static void test_user_fault(void)
{
	struct arena_import *skel;
	int fd, status, ret;
	pid_t pid;

	fd = make_memfd(F_SEAL_SHRINK);
	if (fd < 0)
		return;
	skel = open_skel();
	if (!skel)
		goto out;

	if (!ASSERT_OK(do_import(skel, fd, 0, 1, 1), "import"))
		goto out;

	pid = fork();
	if (!ASSERT_GE(pid, 0, "fork"))
		goto out;
	if (!pid) {
		/* The arena mapping is not inherited, map it again */
		struct sigaction sa = { .sa_sigaction = fault_handler, .sa_flags = SA_SIGINFO };
		size_t sz = bpf_map__max_entries(skel->maps.arena) * ps;
		char *p;

		p = mmap(skel->bss->base, sz, PROT_READ | PROT_WRITE,
			 MAP_SHARED | MAP_FIXED, bpf_map__fd(skel->maps.arena), 0);
		if (p == MAP_FAILED || sigaction(SIGBUS, &sa, NULL))
			_exit(1);
		/* Test pages 0 and 1, see page_addr() */
		p[ps] = 1;	/* allocated on demand */
		fault_expected = p + 2 * ps;
		/* Set before the store that faults */
		atomic_signal_fence(memory_order_seq_cst);
		p[2 * ps] = 1;	/* imported */
		_exit(2);
	}
	/* The watchdog of the runner interrupts system calls */
	do {
		ret = waitpid(pid, &status, 0);
	} while (ret < 0 && errno == EINTR);
	if (ASSERT_EQ(ret, pid, "waitpid")) {
		ASSERT_TRUE(WIFEXITED(status), "exited");
		/* 3: SIGBUS on the imported page, 4: elsewhere, 2: no fault */
		ASSERT_EQ(WEXITSTATUS(status), 3, "sigbus_on_imported");
	}
out:
	arena_import__destroy(skel);
	close(fd);
}

/*
 * Only a device-dax mapping can be imported by address. This needs no
 * device-dax device: it only checks that everything else is refused.
 */
static void test_dax_invalid(void)
{
	char *anon = MAP_FAILED, *shm = MAP_FAILED;
	struct arena_import *skel;
	int fd = -1;

	skel = open_skel();
	if (!skel)
		return;

	anon = mmap(NULL, 2 * ps, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (!ASSERT_NEQ(anon, MAP_FAILED, "mmap_anon"))
		goto out;
	anon[0] = 1;
	ASSERT_EQ(do_import_dax(skel, anon, 0, 1), -EINVAL, "anon");
	ASSERT_EQ(do_import_dax(skel, anon + 1, 0, 1), -EINVAL, "unaligned_src");
	ASSERT_EQ(do_import_dax(skel, anon, 0, 0), -EINVAL, "zero_pages");
	ASSERT_EQ(do_import_dax(skel, anon, 0, bpf_map__max_entries(skel->maps.arena) + 1),
		  -EINVAL, "too_many_pages");
	if (ASSERT_OK(munmap(anon + ps, ps), "munmap"))
		ASSERT_EQ(do_import_dax(skel, anon + ps, 0, 1), -EINVAL, "unmapped");

	/* Memory with a file behind it is imported by file */
	fd = make_memfd(F_SEAL_SHRINK);
	if (fd < 0)
		goto out;
	shm = mmap(NULL, ps, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (ASSERT_NEQ(shm, MAP_FAILED, "mmap_memfd"))
		ASSERT_EQ(do_import_dax(skel, shm, 0, 1), -EINVAL, "memfd");

	/* Nothing above may leave a range behind */
	ASSERT_OK(do_alloc(skel, 0, 8), "alloc_all");
out:
	if (shm != MAP_FAILED)
		munmap(shm, ps);
	/* Both pages, the second one may still be mapped */
	if (anon != MAP_FAILED)
		munmap(anon, 2 * ps);
	if (fd >= 0)
		close(fd);
	arena_import__destroy(skel);
}

void serial_test_arena_import(void)
{
	ps = sysconf(_SC_PAGESIZE);

	if (test__start_subtest("share"))
		test_share();
	if (test__start_subtest("free"))
		test_free();
	if (test__start_subtest("invalid"))
		test_invalid();
	if (test__start_subtest("user_fault"))
		test_user_fault();
	if (test__start_subtest("dax_invalid"))
		test_dax_invalid();
}
