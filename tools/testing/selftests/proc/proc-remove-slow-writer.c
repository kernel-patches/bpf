// SPDX-License-Identifier: GPL-2.0
/*
 * A write that faults while procfs copies it in must not hold up removal of
 * the /proc entry. Removing a scsi_debug host removes its
 * /proc/scsi/scsi_debug/<host> file.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "../kselftest_harness.h"

#define ADD_HOST	"/sys/bus/pseudo/drivers/scsi_debug/add_host"
#define HOST_DIR	"/proc/scsi/scsi_debug"
#define TIMEOUT_MS	5000
#define MAX_HOSTS	4096
#define HOST_BITS	(8 * sizeof(unsigned long))

struct writer {
	int fd;
	char *buf;
	ssize_t ret;
	int err;
};

struct remover {
	int done;
	int ret;
};

/* a positive @nr adds hosts, a negative one removes the last ones added */
static int add_host(int nr)
{
	char s[16];
	int fd, len, ret;

	fd = open(ADD_HOST, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	len = snprintf(s, sizeof(s), "%d", nr);
	ret = write(fd, s, len) == len ? 0 : -errno;
	close(fd);
	return ret;
}

/* the numbers of the hosts in /proc/scsi/scsi_debug as a bitmap */
static int list_hosts(unsigned long *hosts)
{
	struct dirent *d;
	DIR *dir;

	memset(hosts, 0, MAX_HOSTS / 8);
	dir = opendir(HOST_DIR);
	if (!dir)
		/* the directory comes with the first host and goes with the last */
		return errno == ENOENT ? 0 : -errno;
	while ((d = readdir(dir))) {
		char *end;
		long nr = strtol(d->d_name, &end, 10);

		if (end != d->d_name && !*end && nr >= 0 && nr < MAX_HOSTS)
			hosts[nr / HOST_BITS] |= 1UL << (nr % HOST_BITS);
	}
	closedir(dir);
	return 0;
}

/* the host that is in @after but wasn't in @before */
static int new_host(const unsigned long *before, const unsigned long *after)
{
	for (int i = 0; i < MAX_HOSTS / HOST_BITS; i++) {
		unsigned long new = after[i] & ~before[i];

		if (new)
			return i * HOST_BITS + __builtin_ctzl(new);
	}
	return -1;
}

static void *write_thread(void *arg)
{
	struct writer *w = arg;

	w->ret = write(w->fd, w->buf, 2);
	w->err = errno;
	return NULL;
}

static void *remove_thread(void *arg)
{
	struct remover *r = arg;
	ssize_t ret;

	r->ret = add_host(-1);
	ret = write(r->done, "x", 1);
	return (void *)ret;
}

FIXTURE(host) {
	char path[PATH_MAX];
	int host;
};

FIXTURE_SETUP(host)
{
	unsigned long before[MAX_HOSTS / HOST_BITS];
	unsigned long after[MAX_HOSTS / HOST_BITS];

	self->host = -1;
	if (access(ADD_HOST, W_OK) && system("modprobe -q scsi_debug add_host=0"))
		SKIP(return, "no scsi_debug");
	if (access(ADD_HOST, W_OK))
		SKIP(return, ADD_HOST ": %s", strerror(errno));
	/* the host files need CONFIG_SCSI_PROC_FS */
	if (access("/proc/scsi", F_OK))
		SKIP(return, "/proc/scsi: %s", strerror(errno));

	/* host numbers are reused, so look for the one that's new */
	ASSERT_EQ(list_hosts(before), 0);
	ASSERT_EQ(add_host(1), 0);
	if (!list_hosts(after))
		self->host = new_host(before, after);
	/* the teardown doesn't run when the setup fails */
	if (self->host < 0)
		add_host(-1);
	ASSERT_GE(self->host, 0);
	snprintf(self->path, sizeof(self->path), HOST_DIR "/%d", self->host);
}

FIXTURE_TEARDOWN(host)
{
	if (self->host >= 0 && !access(self->path, F_OK))
		add_host(-1);
}

TEST_F(host, remove_while_writer_faults)
{
	struct uffdio_api api = { .api = UFFD_API };
	struct uffdio_register reg = {};
	struct uffdio_zeropage zero = {};
	long psz = sysconf(_SC_PAGESIZE);
	struct writer w = {};
	struct remover r = {};
	struct uffd_msg msg;
	struct pollfd pfd;
	pthread_t wt, rt;
	int uffd, done[2];
	char *buf;

	w.fd = open(self->path, O_WRONLY | O_CLOEXEC);
	if (w.fd < 0)
		SKIP(return, "%s: %s", self->path, strerror(errno));

	uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
	if (uffd < 0)
		SKIP(return, "userfaultfd: %s", strerror(errno));
	ASSERT_EQ(ioctl(uffd, UFFDIO_API, &api), 0);

	buf = mmap(NULL, psz, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	ASSERT_NE(buf, MAP_FAILED);
	reg.range.start = (unsigned long)buf;
	reg.range.len = psz;
	reg.mode = UFFDIO_REGISTER_MODE_MISSING;
	ASSERT_EQ(ioctl(uffd, UFFDIO_REGISTER, &reg), 0);

	w.buf = buf;
	ASSERT_EQ(pthread_create(&wt, NULL, write_thread, &w), 0);

	/* The writer now sleeps while what it writes is copied in. */
	pfd = (struct pollfd){ .fd = uffd, .events = POLLIN };
	ASSERT_EQ(poll(&pfd, 1, TIMEOUT_MS), 1);
	ASSERT_EQ(read(uffd, &msg, sizeof(msg)), sizeof(msg));
	ASSERT_EQ(msg.event, UFFD_EVENT_PAGEFAULT);

	/* Removing the host removes the file that is being written. */
	ASSERT_EQ(pipe2(done, O_CLOEXEC), 0);
	r.done = done[1];
	ASSERT_EQ(pthread_create(&rt, NULL, remove_thread, &r), 0);
	pfd = (struct pollfd){ .fd = done[0], .events = POLLIN };
	EXPECT_EQ(poll(&pfd, 1, TIMEOUT_MS), 1) {
		TH_LOG("removing %s waited for the writer", self->path);
	}

	zero.range.start = (unsigned long)buf;
	zero.range.len = psz;
	ASSERT_EQ(ioctl(uffd, UFFDIO_ZEROPAGE, &zero), 0);
	ASSERT_EQ(pthread_join(wt, NULL), 0);
	ASSERT_EQ(pthread_join(rt, NULL), 0);
	EXPECT_EQ(r.ret, 0);

	/* The entry was gone by the time the write got to it. */
	EXPECT_EQ(w.ret, -1);
	EXPECT_EQ(w.err, EIO);
}

TEST_HARNESS_MAIN
