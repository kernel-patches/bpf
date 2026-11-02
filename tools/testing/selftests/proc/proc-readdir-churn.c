// SPDX-License-Identifier: GPL-2.0
/*
 * A listing of a /proc directory that takes more than one getdents64()
 * must not show an entry twice or skip one when an entry is added or
 * removed in between, and a listing must go on after an entry that is
 * removed while it is being emitted. /proc/net/dev_snmp6/<dev> of a tun
 * device comes and goes with the device.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "../kselftest_harness.h"

#define SNMP6_DIR	"/proc/net/dev_snmp6"
#define TUN_NAME	"a0"		/* sorts before "lo" */
#define TUN_PATH	SNMP6_DIR "/" TUN_NAME
#define SMALL_BUF	80		/* ".", ".." and one short name */
#define NAMES		64
#ifndef MAP_32BIT
#define MAP_32BIT	0
#endif

static int tun_open(const char *name)
{
	struct ifreq ifr = {};
	int fd;

	fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return -1;
	strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	if (ioctl(fd, TUNSETIFF, &ifr)) {
		close(fd);
		return -1;
	}
	return fd;
}

/* one getdents64() into @buf, the names appended to @names */
static int list(int fd, char *buf, size_t size, char names[][NAME_MAX + 1],
		int *n)
{
	long ret, off;
	int got = 0;

	ret = syscall(__NR_getdents64, fd, buf, size);
	if (ret < 0)
		return -errno;
	for (off = 0; off < ret;) {
		struct dirent64 *d = (void *)(buf + off);

		if (*n < NAMES)
			strcpy(names[(*n)++], d->d_name);
		got++;
		off += d->d_reclen;
	}
	return got;
}

static int count(char names[][NAME_MAX + 1], int n, const char *name)
{
	int i, c = 0;

	for (i = 0; i < n; i++)
		if (!strcmp(names[i], name))
			c++;
	return c;
}

/* removes the device once getdents64() faults on its entry, then resolves */
struct stall {
	int uffd;
	int tun;
	unsigned long addr;
	unsigned long len;
	int removed;
};

static void *stall_resolve(void *arg)
{
	struct stall *s = arg;
	struct pollfd pfd = { .fd = s->uffd, .events = POLLIN };
	struct uffdio_zeropage zero = {
		.range = { .start = s->addr, .len = s->len },
	};
	struct uffd_msg msg;

	if (poll(&pfd, 1, 10000) != 1)
		return NULL;
	if (read(s->uffd, &msg, sizeof(msg)) != sizeof(msg) ||
	    msg.event != UFFD_EVENT_PAGEFAULT)
		return NULL;
	close(s->tun);
	s->removed = access(TUN_PATH, F_OK) == -1;
	ioctl(s->uffd, UFFDIO_ZEROPAGE, &zero);
	return NULL;
}

FIXTURE(proc_readdir) {
	int dir;
	int n;
	char names[NAMES][NAME_MAX + 1];
	char buf[65536];
};

FIXTURE_SETUP(proc_readdir)
{
	int tun;

	if (unshare(CLONE_NEWNET))
		SKIP(return, "unshare(CLONE_NEWNET): %s", strerror(errno));
	tun = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
	if (tun < 0)
		SKIP(return, "/dev/net/tun: %s", strerror(errno));
	close(tun);
	self->dir = open(SNMP6_DIR, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (self->dir < 0)
		SKIP(return, SNMP6_DIR ": %s", strerror(errno));
	self->n = 0;
}

FIXTURE_TEARDOWN(proc_readdir)
{
	close(self->dir);
}

/* a device added in front of the position doesn't repeat an entry */
TEST_F(proc_readdir, add_in_front)
{
	int tun;

	/* ".", ".." and "lo" */
	ASSERT_EQ(list(self->dir, self->buf, SMALL_BUF, self->names, &self->n), 3);
	ASSERT_EQ(count(self->names, self->n, "lo"), 1);

	tun = tun_open(TUN_NAME);
	ASSERT_GE(tun, 0);
	ASSERT_EQ(access(TUN_PATH, F_OK), 0);

	while (list(self->dir, self->buf, sizeof(self->buf), self->names,
		    &self->n) > 0)
		;
	EXPECT_EQ(count(self->names, self->n, "lo"), 1);
	close(tun);
}

/* a device removed in front of the position doesn't skip an entry */
TEST_F(proc_readdir, remove_in_front)
{
	int tun;

	tun = tun_open(TUN_NAME);
	ASSERT_GE(tun, 0);
	ASSERT_EQ(access(TUN_PATH, F_OK), 0);

	/* ".", ".." and the device, "lo" doesn't fit */
	ASSERT_EQ(list(self->dir, self->buf, SMALL_BUF, self->names, &self->n), 3);
	ASSERT_EQ(count(self->names, self->n, TUN_NAME), 1);

	/* closing the device unregisters it and removes its entry */
	close(tun);
	ASSERT_EQ(access(TUN_PATH, F_OK), -1);

	while (list(self->dir, self->buf, sizeof(self->buf), self->names,
		    &self->n) > 0)
		;
	EXPECT_EQ(count(self->names, self->n, "lo"), 1);
}

/* the entry being emitted is removed meanwhile, the listing goes on */
TEST_F(proc_readdir, remove_current)
{
	struct uffdio_api api = { .api = UFFD_API };
	struct uffdio_register reg = {};
	long page = sysconf(_SC_PAGESIZE);
	struct stall s = {};
	pthread_t thread;
	char *map;
	long ret, off;

	s.uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
	if (s.uffd < 0)
		SKIP(return, "userfaultfd: %s", strerror(errno));
	ASSERT_EQ(ioctl(s.uffd, UFFDIO_API, &api), 0);

	/* the first page is there, the second one faults */
	map = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	ASSERT_NE(map, MAP_FAILED);
	map[0] = 0;
	s.addr = (unsigned long)map + page;
	s.len = page;
	reg.range.start = s.addr;
	reg.range.len = s.len;
	reg.mode = UFFDIO_REGISTER_MODE_MISSING;
	ASSERT_EQ(ioctl(s.uffd, UFFDIO_REGISTER, &reg), 0);

	s.tun = tun_open(TUN_NAME);
	ASSERT_GE(s.tun, 0);
	ASSERT_EQ(access(TUN_PATH, F_OK), 0);
	ASSERT_EQ(pthread_create(&thread, NULL, stall_resolve, &s), 0);

	/*
	 * ".." ends right before the second page, so writing the record of
	 * the device stalls until it has been removed.
	 */
	ret = syscall(__NR_getdents64, self->dir, map + page - 48, 48 + page);
	ASSERT_EQ(pthread_join(thread, NULL), 0);
	ASSERT_TRUE(s.removed);
	ASSERT_GT(ret, 0);
	for (off = 0; off < ret;) {
		struct dirent64 *d = (void *)(map + page - 48 + off);

		if (self->n < NAMES)
			strcpy(self->names[self->n++], d->d_name);
		off += d->d_reclen;
	}
	ASSERT_EQ(count(self->names, self->n, TUN_NAME), 1);

	while (list(self->dir, self->buf, sizeof(self->buf), self->names,
		    &self->n) > 0)
		;
	EXPECT_EQ(count(self->names, self->n, "lo"), 1);
	munmap(map, 2 * page);
	close(s.uffd);
}

/*
 * The old readdir(2) hands userspace what ->iterate_shared() returned
 * when it wrote no entry, so a listing has to end with 0 there and not
 * with the 1 that proc_readdir_de() uses to tell the /proc root to go
 * on with the pids. x86_64 only has the syscall in its 32-bit table.
 */
struct old_dirent32 {
	uint32_t d_ino;
	uint32_t d_off;
	uint16_t d_namlen;
	char d_name[NAME_MAX + 1];
};

static sigjmp_buf no_int80;

static void no_int80_handler(int sig)
{
	siglongjmp(no_int80, 1);
}

/* one entry, 0 at the end, or -errno */
static long old_readdir(int fd, struct old_dirent32 *d)
{
#if defined(__i386__) && defined(SYS_readdir)
	long ret = syscall(SYS_readdir, fd, d, 1);

	return ret < 0 ? -errno : ret;
#elif defined(__x86_64__)
	long ret;

	asm volatile("int $0x80"
		     : "=a" (ret)
		     : "0" (89), "b" (fd), "c" ((uint32_t)(uintptr_t)d), "d" (1)
		     : "memory");
	return ret;
#else
	return -ENOSYS;
#endif
}

TEST(readdir_eof)
{
	static const char *const dirs[] = {
		"/proc/fs", "/proc/self/net", "/proc/sys", "/proc",
	};
	struct old_dirent32 *d;
	long ret;
	int i;

	d = mmap(NULL, sizeof(*d), PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
	ASSERT_NE(d, MAP_FAILED);
	if (sigsetjmp(no_int80, 1)) {
		signal(SIGSEGV, SIG_DFL);
		SKIP(return, "no 32-bit syscalls");
	}
	signal(SIGSEGV, no_int80_handler);
	ret = old_readdir(-1, d);
	signal(SIGSEGV, SIG_DFL);
	if (ret == -ENOSYS)
		SKIP(return, "no readdir(2)");
	ASSERT_EQ(ret, -EBADF);

	for (i = 0; i < ARRAY_SIZE(dirs); i++) {
		int fd = open(dirs[i], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		long n;

		if (fd < 0) {
			TH_LOG("%s: %s", dirs[i], strerror(errno));
			continue;
		}
		for (n = 0; n < 1 << 20; n++) {
			d->d_namlen = 0;
			ret = old_readdir(fd, d);
			if (ret <= 0)
				break;
			/* a 1 means one entry was written */
			ASSERT_EQ(ret, 1) TH_LOG("%s", dirs[i]);
			ASSERT_NE(d->d_namlen, 0)
				TH_LOG("%s after %ld entries", dirs[i], n);
		}
		EXPECT_EQ(ret, 0) TH_LOG("%s after %ld entries", dirs[i], n);
		close(fd);
	}
	munmap(d, sizeof(*d));
}

TEST_HARNESS_MAIN
