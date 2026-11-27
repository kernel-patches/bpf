// SPDX-License-Identifier: GPL-2.0
/*
 * A readlink() that faults while copying out the link must not hold up
 * removal of the /proc symlink. Changing a sound card's id removes
 * /proc/asound/<id> with snd_card_mutex and info_mutex held.
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

#define CARD_ID		"Dummy"
#define NEW_ID		"procslow"
#define LINK_PATH	"/proc/asound/" CARD_ID
#define TIMEOUT_MS	5000

struct reader {
	char *buf;
	size_t len;
	ssize_t ret;
};

struct renamer {
	const char *id_path;
	const char *id;
	int done;
	int ret;
};

static void *readlink_thread(void *arg)
{
	struct reader *r = arg;

	r->ret = readlink(LINK_PATH, r->buf, r->len);
	return NULL;
}

/* a new id removes the card's old /proc/asound/<id> link */
static int set_id(const char *id_path, const char *id)
{
	int fd, ret;

	fd = open(id_path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	ret = write(fd, id, strlen(id)) < 0 ? -errno : 0;
	close(fd);
	return ret;
}

static void *rename_thread(void *arg)
{
	struct renamer *r = arg;
	ssize_t ret;

	r->ret = set_id(r->id_path, r->id);
	ret = write(r->done, "x", 1);
	return (void *)ret;
}

/* the sysfs id file of the card with @id */
static int find_card(const char *id, char *id_path, size_t size)
{
	struct dirent *d;
	int ret = -1;
	DIR *dir;

	dir = opendir("/sys/class/sound");
	if (!dir)
		return -1;
	while (ret && (d = readdir(dir))) {
		char cur[32];
		FILE *f;

		if (strncmp(d->d_name, "card", 4))
			continue;
		snprintf(id_path, size, "/sys/class/sound/%s/id", d->d_name);
		f = fopen(id_path, "r");
		if (!f)
			continue;
		if (fgets(cur, sizeof(cur), f)) {
			cur[strcspn(cur, "\n")] = '\0';
			if (!strcmp(cur, id))
				ret = 0;
		}
		fclose(f);
	}
	closedir(dir);
	return ret;
}

FIXTURE(dummy) {
	char id_path[PATH_MAX];
	bool renamed;
};

FIXTURE_SETUP(dummy)
{
	self->renamed = false;
	if (access(LINK_PATH, F_OK) && system("modprobe -q snd-dummy"))
		SKIP(return, "no snd-dummy");
	if (access(LINK_PATH, F_OK))
		SKIP(return, LINK_PATH ": %s", strerror(errno));
	if (find_card(CARD_ID, self->id_path, sizeof(self->id_path)))
		SKIP(return, "no sysfs id file for " CARD_ID);
	if (access(self->id_path, W_OK))
		SKIP(return, "%s: %s", self->id_path, strerror(errno));
}

FIXTURE_TEARDOWN(dummy)
{
	if (self->renamed && set_id(self->id_path, CARD_ID))
		TH_LOG("couldn't name the card " CARD_ID " again");
}

TEST_F(dummy, remove_while_readlink_faults)
{
	struct uffdio_api api = { .api = UFFD_API };
	struct uffdio_register reg = {};
	struct uffdio_zeropage zero = {};
	long psz = sysconf(_SC_PAGESIZE);
	struct renamer rn = {};
	struct reader r = {};
	struct uffd_msg msg;
	struct pollfd pfd;
	pthread_t rt, nt;
	int uffd, done[2];
	char *buf;

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

	r.buf = buf;
	r.len = psz;
	ASSERT_EQ(pthread_create(&rt, NULL, readlink_thread, &r), 0);

	/* The reader now sleeps in the copy of the link to userspace. */
	pfd = (struct pollfd){ .fd = uffd, .events = POLLIN };
	ASSERT_EQ(poll(&pfd, 1, TIMEOUT_MS), 1);
	ASSERT_EQ(read(uffd, &msg, sizeof(msg)), sizeof(msg));
	ASSERT_EQ(msg.event, UFFD_EVENT_PAGEFAULT);

	/* Renaming the card removes the link that is being read. */
	ASSERT_EQ(pipe2(done, O_CLOEXEC), 0);
	rn.id_path = self->id_path;
	rn.id = NEW_ID;
	rn.done = done[1];
	self->renamed = true;
	ASSERT_EQ(pthread_create(&nt, NULL, rename_thread, &rn), 0);
	pfd = (struct pollfd){ .fd = done[0], .events = POLLIN };
	EXPECT_EQ(poll(&pfd, 1, TIMEOUT_MS), 1) {
		TH_LOG("removing " LINK_PATH " waited for the reader");
	}

	zero.range.start = (unsigned long)buf;
	zero.range.len = psz;
	ASSERT_EQ(ioctl(uffd, UFFDIO_ZEROPAGE, &zero), 0);
	ASSERT_EQ(pthread_join(rt, NULL), 0);
	ASSERT_EQ(pthread_join(nt, NULL), 0);
	EXPECT_EQ(rn.ret, 0);

	/* The link was read before it went away. */
	EXPECT_GT(r.ret, 0);
	EXPECT_EQ(readlink(LINK_PATH, buf, psz), -1);
	EXPECT_EQ(errno, ENOENT);
}

TEST_HARNESS_MAIN
