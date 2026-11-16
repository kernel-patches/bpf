// SPDX-License-Identifier: GPL-2.0
/*
 * A read that faults while procfs copies it to userspace must not hold up
 * removal of the /proc entry. Unloading configs.ko removes /proc/config.gz,
 * which isn't a seq_file.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "../kselftest_harness.h"

#define CONFIG_PATH	"/proc/config.gz"
#define CONFIG_MODULE	"/sys/module/configs"
#define READ_PAGES	2
#define TIMEOUT_MS	5000

struct reader {
	int fd;
	char *buf;
	size_t len;
	ssize_t ret;
};

struct unloader {
	int done;
	int ret;
};

static void *read_thread(void *arg)
{
	struct reader *r = arg;

	r->ret = read(r->fd, r->buf, r->len);
	return NULL;
}

static void *unload_thread(void *arg)
{
	struct unloader *u = arg;
	ssize_t ret;

	u->ret = syscall(__NR_delete_module, "configs", O_NONBLOCK) ? -errno : 0;
	ret = write(u->done, "x", 1);
	return (void *)ret;
}

FIXTURE(configs) {
	bool loaded;
};

FIXTURE_SETUP(configs)
{
	self->loaded = false;
	if (access(CONFIG_PATH, R_OK) && system("modprobe -q configs"))
		SKIP(return, "no " CONFIG_PATH);
	if (access(CONFIG_PATH, R_OK))
		SKIP(return, CONFIG_PATH ": %s", strerror(errno));
	if (access(CONFIG_MODULE, F_OK))
		SKIP(return, "configs isn't a module");
	self->loaded = true;
}

FIXTURE_TEARDOWN(configs)
{
	/* an ASSERT may have fired with the module unloaded */
	if (self->loaded && access(CONFIG_PATH, F_OK) &&
	    system("modprobe -q configs"))
		TH_LOG("couldn't load configs again");
}

TEST_F(configs, remove_while_reader_faults)
{
	struct uffdio_api api = { .api = UFFD_API };
	struct uffdio_register reg = {};
	struct uffdio_zeropage zero = {};
	long psz = sysconf(_SC_PAGESIZE);
	struct unloader u = {};
	struct reader r = {};
	struct uffd_msg msg;
	struct pollfd pfd;
	pthread_t rt, ut;
	int uffd, done[2];
	char *buf, *ref;
	ssize_t ref_len;

	r.fd = open(CONFIG_PATH, O_RDONLY | O_CLOEXEC);
	ASSERT_GE(r.fd, 0);

	/* what the first page of a read looks like */
	ref = malloc(psz);
	ASSERT_NE(ref, NULL);
	ref_len = pread(r.fd, ref, psz, 0);
	ASSERT_GT(ref_len, 0);

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

	/* The reader now sleeps in the copy to userspace. */
	pfd = (struct pollfd){ .fd = uffd, .events = POLLIN };
	ASSERT_EQ(poll(&pfd, 1, TIMEOUT_MS), 1);
	ASSERT_EQ(read(uffd, &msg, sizeof(msg)), sizeof(msg));
	ASSERT_EQ(msg.event, UFFD_EVENT_PAGEFAULT);

	/* Unloading configs.ko removes the file that is being read. */
	ASSERT_EQ(pipe2(done, O_CLOEXEC), 0);
	u.done = done[1];
	ASSERT_EQ(pthread_create(&ut, NULL, unload_thread, &u), 0);
	pfd = (struct pollfd){ .fd = done[0], .events = POLLIN };
	EXPECT_EQ(poll(&pfd, 1, TIMEOUT_MS), 1) {
		TH_LOG("removing " CONFIG_PATH " waited for the reader");
	}

	zero.range.start = (unsigned long)buf;
	zero.range.len = psz;
	ASSERT_EQ(ioctl(uffd, UFFDIO_ZEROPAGE, &zero), 0);
	ASSERT_EQ(pthread_join(rt, NULL), 0);
	ASSERT_EQ(pthread_join(ut, NULL), 0);
	if (u.ret)
		SKIP(return, "unloading configs: %s", strerror(-u.ret));

	/*
	 * The page that was read before the removal still arrives and the
	 * next piece isn't filled anymore, then nothing.
	 */
	EXPECT_EQ(r.ret, ref_len);
	EXPECT_EQ(memcmp(buf, ref, ref_len), 0);
	EXPECT_EQ(read(r.fd, buf, psz), -1);
	EXPECT_EQ(errno, EIO);
	free(ref);
}

TEST_HARNESS_MAIN
