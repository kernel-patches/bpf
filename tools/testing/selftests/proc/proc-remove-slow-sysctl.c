// SPDX-License-Identifier: GPL-2.0
/*
 * A read(), write() or getdents64() of /proc/sys that faults while copying
 * from or to userspace must not hold up unregistering the sysctl table.
 * /proc/sys/net/ipv6/conf/<dev>/ of a tun device is unregistered under RTNL
 * when the device's file is closed.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "../kselftest_harness.h"

#define TUN_NAME	"procslow0"
#define CONF_PATH	"/proc/sys/net/ipv6/conf/" TUN_NAME
#define MTU_PATH	CONF_PATH "/mtu"
#define BUF_PAGES	16
#define TIMEOUT_MS	5000

enum sysctl_op {
	SYSCTL_READ,
	SYSCTL_WRITE,
	SYSCTL_GETDENTS,
};

struct worker {
	enum sysctl_op op;
	int fd;
	char *buf;
	size_t len;
	ssize_t ret;
	int err;
};

struct closer {
	int tun;
	int done;
};

static void *work_thread(void *arg)
{
	struct worker *w = arg;

	switch (w->op) {
	case SYSCTL_READ:
		w->ret = read(w->fd, w->buf, w->len);
		break;
	case SYSCTL_WRITE:
		w->ret = write(w->fd, w->buf, w->len);
		break;
	case SYSCTL_GETDENTS:
		w->ret = syscall(__NR_getdents64, w->fd, w->buf, w->len);
		break;
	}
	w->err = errno;
	return NULL;
}

static void *close_thread(void *arg)
{
	struct closer *c = arg;
	ssize_t ret;

	close(c->tun);
	ret = write(c->done, "x", 1);
	return (void *)ret;
}

FIXTURE(proc_sys_slow) {
	int tun;
	int uffd;
	char *buf;
	long psz;
};

FIXTURE_SETUP(proc_sys_slow)
{
	struct uffdio_api api = { .api = UFFD_API };
	struct uffdio_register reg = {};
	struct ifreq ifr = {};

	if (unshare(CLONE_NEWNET))
		SKIP(return, "unshare(CLONE_NEWNET): %s", strerror(errno));

	self->tun = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
	if (self->tun < 0)
		SKIP(return, "/dev/net/tun: %s", strerror(errno));
	strncpy(ifr.ifr_name, TUN_NAME, IFNAMSIZ - 1);
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	ASSERT_EQ(ioctl(self->tun, TUNSETIFF, &ifr), 0);
	if (access(CONF_PATH, F_OK))
		SKIP(return, CONF_PATH ": %s", strerror(errno));

	self->uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
	if (self->uffd < 0)
		SKIP(return, "userfaultfd: %s", strerror(errno));
	ASSERT_EQ(ioctl(self->uffd, UFFDIO_API, &api), 0);

	/* Only the first page of the buffer goes through userfaultfd. */
	self->psz = sysconf(_SC_PAGESIZE);
	self->buf = mmap(NULL, BUF_PAGES * self->psz, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	ASSERT_NE(self->buf, MAP_FAILED);
	reg.range.start = (unsigned long)self->buf;
	reg.range.len = self->psz;
	reg.mode = UFFDIO_REGISTER_MODE_MISSING;
	ASSERT_EQ(ioctl(self->uffd, UFFDIO_REGISTER, &reg), 0);
}

FIXTURE_TEARDOWN(proc_sys_slow)
{
}

/*
 * Let @w sleep in its copy from or to the first page of the buffer, then
 * close the device. Unregistering the table must not wait for @w.
 */
static void stall_and_remove(struct __test_metadata *_metadata,
			     FIXTURE_DATA(proc_sys_slow) *self,
			     struct worker *w)
{
	struct closer c = { .tun = self->tun };
	struct uffdio_zeropage zero = {};
	struct uffd_msg msg;
	struct pollfd pfd;
	pthread_t wt, ct;
	int done[2];

	w->buf = self->buf;
	ASSERT_EQ(pthread_create(&wt, NULL, work_thread, w), 0);

	pfd = (struct pollfd){ .fd = self->uffd, .events = POLLIN };
	ASSERT_EQ(poll(&pfd, 1, TIMEOUT_MS), 1);
	ASSERT_EQ(read(self->uffd, &msg, sizeof(msg)), sizeof(msg));
	ASSERT_EQ(msg.event, UFFD_EVENT_PAGEFAULT);

	ASSERT_EQ(pipe2(done, O_CLOEXEC), 0);
	c.done = done[1];
	ASSERT_EQ(pthread_create(&ct, NULL, close_thread, &c), 0);
	pfd = (struct pollfd){ .fd = done[0], .events = POLLIN };
	EXPECT_EQ(poll(&pfd, 1, TIMEOUT_MS), 1) {
		TH_LOG("unregistering " CONF_PATH " waited for the faulting task");
	}

	zero.range.start = (unsigned long)self->buf;
	zero.range.len = self->psz;
	ASSERT_EQ(ioctl(self->uffd, UFFDIO_ZEROPAGE, &zero), 0);
	ASSERT_EQ(pthread_join(wt, NULL), 0);
	ASSERT_EQ(pthread_join(ct, NULL), 0);
}

TEST_F(proc_sys_slow, read)
{
	struct worker w = {
		.op	= SYSCTL_READ,
		.len	= BUF_PAGES * self->psz,
	};

	w.fd = open(MTU_PATH, O_RDONLY | O_CLOEXEC);
	ASSERT_GE(w.fd, 0);
	stall_and_remove(_metadata, self, &w);

	/* The value was produced before the table went away, then nothing. */
	EXPECT_GT(w.ret, 0);
	EXPECT_EQ(read(w.fd, self->buf, self->psz), -1);
	EXPECT_EQ(errno, ENOENT);
}

TEST_F(proc_sys_slow, write)
{
	struct worker w = {
		.op	= SYSCTL_WRITE,
		.len	= 5,
	};

	w.fd = open(MTU_PATH, O_WRONLY | O_CLOEXEC);
	ASSERT_GE(w.fd, 0);
	stall_and_remove(_metadata, self, &w);

	/* The table went away while the value was copied in. */
	EXPECT_EQ(w.ret, -1);
	EXPECT_EQ(w.err, ENOENT);
}

TEST_F(proc_sys_slow, getdents)
{
	struct worker w = {
		.op	= SYSCTL_GETDENTS,
		.len	= BUF_PAGES * self->psz,
	};

	w.fd = open(CONF_PATH, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ASSERT_GE(w.fd, 0);
	/* start behind the dots so that it faults on an entry it looked up */
	ASSERT_EQ(lseek(w.fd, 2, SEEK_SET), 2);
	stall_and_remove(_metadata, self, &w);

	/* What was looked up before the removal still arrives, then nothing. */
	EXPECT_GT(w.ret, 0);
	EXPECT_EQ(syscall(__NR_getdents64, w.fd, self->buf, self->psz), -1);
	EXPECT_EQ(errno, ENOENT);
}

TEST_HARNESS_MAIN
