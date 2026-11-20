// SPDX-License-Identifier: GPL-2.0
/*
 * A read that faults while copying to userspace must not hold up removal of
 * the /proc entry. /proc/net/dev_snmp6/<dev> of a tun device is removed under
 * RTNL when the device's file is closed.
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
#define SNMP6_PATH	"/proc/net/dev_snmp6/" TUN_NAME
#define READ_PAGES	16
#define TIMEOUT_MS	5000

struct reader {
	int fd;
	char *buf;
	size_t len;
	ssize_t ret;
};

struct closer {
	int tun;
	int done;
};

static void *read_thread(void *arg)
{
	struct reader *r = arg;

	r->ret = read(r->fd, r->buf, r->len);
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

TEST(remove_while_reader_faults)
{
	struct uffdio_api api = { .api = UFFD_API };
	struct uffdio_register reg = {};
	struct uffdio_zeropage zero = {};
	long psz = sysconf(_SC_PAGESIZE);
	struct ifreq ifr = {};
	struct reader r = {};
	struct closer c = {};
	struct uffd_msg msg;
	struct pollfd pfd;
	pthread_t rt, ct;
	int uffd, done[2];
	char *buf;

	if (unshare(CLONE_NEWNET))
		SKIP(return, "unshare(CLONE_NEWNET): %s", strerror(errno));

	c.tun = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
	if (c.tun < 0)
		SKIP(return, "/dev/net/tun: %s", strerror(errno));
	strncpy(ifr.ifr_name, TUN_NAME, IFNAMSIZ - 1);
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	ASSERT_EQ(ioctl(c.tun, TUNSETIFF, &ifr), 0);

	r.fd = open(SNMP6_PATH, O_RDONLY | O_CLOEXEC);
	if (r.fd < 0)
		SKIP(return, SNMP6_PATH ": %s", strerror(errno));

	uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
	if (uffd < 0)
		SKIP(return, "userfaultfd: %s", strerror(errno));
	ASSERT_EQ(ioctl(uffd, UFFDIO_API, &api), 0);

	/* Only the first page of the buffer goes through userfaultfd. */
	buf = mmap(NULL, READ_PAGES * psz, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	ASSERT_NE(buf, MAP_FAILED);
	reg.range.start = (unsigned long)buf;
	reg.range.len = psz;
	reg.mode = UFFDIO_REGISTER_MODE_MISSING;
	ASSERT_EQ(ioctl(uffd, UFFDIO_REGISTER, &reg), 0);

	r.buf = buf;
	r.len = READ_PAGES * psz;
	ASSERT_EQ(pthread_create(&rt, NULL, read_thread, &r), 0);

	/* The reader now sleeps in its copy to userspace. */
	pfd = (struct pollfd){ .fd = uffd, .events = POLLIN };
	ASSERT_EQ(poll(&pfd, 1, TIMEOUT_MS), 1);
	ASSERT_EQ(read(uffd, &msg, sizeof(msg)), sizeof(msg));
	ASSERT_EQ(msg.event, UFFD_EVENT_PAGEFAULT);

	/* Closing the device removes the file that is being read. */
	ASSERT_EQ(pipe2(done, O_CLOEXEC), 0);
	c.done = done[1];
	ASSERT_EQ(pthread_create(&ct, NULL, close_thread, &c), 0);
	pfd = (struct pollfd){ .fd = done[0], .events = POLLIN };
	EXPECT_EQ(poll(&pfd, 1, TIMEOUT_MS), 1) {
		TH_LOG("removing " SNMP6_PATH " waited for the reader");
	}

	zero.range.start = (unsigned long)buf;
	zero.range.len = psz;
	ASSERT_EQ(ioctl(uffd, UFFDIO_ZEROPAGE, &zero), 0);
	ASSERT_EQ(pthread_join(rt, NULL), 0);
	ASSERT_EQ(pthread_join(ct, NULL), 0);

	/* What was printed before the removal still arrives, then nothing. */
	EXPECT_GT(r.ret, 0);
	EXPECT_EQ(read(r.fd, buf, psz), -1);
	EXPECT_EQ(errno, EIO);
}

TEST_HARNESS_MAIN
