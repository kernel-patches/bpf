// SPDX-License-Identifier: GPL-2.0
/*
 * A listing of a /proc/sys directory that takes more than one getdents64()
 * must not show an entry twice or skip one when an entry is registered or
 * unregistered in between. /proc/sys/net/ipv4/conf/<dev> of a tun device
 * comes and goes with the device.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sched.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "../kselftest_harness.h"

#define CONF_DIR	"/proc/sys/net/ipv4/conf"
#define TUN_NAME	"a0"		/* sorts before "all" */
#define TUN_PATH	CONF_DIR "/" TUN_NAME
#define SMALL_BUF	80		/* ".", ".." and one short name */
#define NAMES		64

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

FIXTURE(sysctl_readdir) {
	int dir;
	int n;
	char names[NAMES][NAME_MAX + 1];
	char buf[65536];
};

FIXTURE_SETUP(sysctl_readdir)
{
	int tun;

	if (unshare(CLONE_NEWNET))
		SKIP(return, "unshare(CLONE_NEWNET): %s", strerror(errno));
	tun = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
	if (tun < 0)
		SKIP(return, "/dev/net/tun: %s", strerror(errno));
	close(tun);
	self->dir = open(CONF_DIR, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (self->dir < 0)
		SKIP(return, CONF_DIR ": %s", strerror(errno));
	self->n = 0;
}

FIXTURE_TEARDOWN(sysctl_readdir)
{
	close(self->dir);
}

/* a device registered in front of the position doesn't repeat an entry */
TEST_F(sysctl_readdir, register_in_front)
{
	int tun;

	/* ".", ".." and "all", "default" doesn't fit */
	ASSERT_EQ(list(self->dir, self->buf, SMALL_BUF, self->names, &self->n), 3);
	ASSERT_EQ(count(self->names, self->n, "all"), 1);

	tun = tun_open(TUN_NAME);
	ASSERT_GE(tun, 0);
	ASSERT_EQ(access(TUN_PATH, F_OK), 0);

	while (list(self->dir, self->buf, sizeof(self->buf), self->names,
		    &self->n) > 0)
		;
	EXPECT_EQ(count(self->names, self->n, "all"), 1);
	EXPECT_EQ(count(self->names, self->n, "default"), 1);
	EXPECT_EQ(count(self->names, self->n, "lo"), 1);
	close(tun);
}

/* a device unregistered in front of the position doesn't skip an entry */
TEST_F(sysctl_readdir, unregister_in_front)
{
	int tun;

	tun = tun_open(TUN_NAME);
	ASSERT_GE(tun, 0);
	ASSERT_EQ(access(TUN_PATH, F_OK), 0);

	/* ".", ".." and the device, "all" doesn't fit */
	ASSERT_EQ(list(self->dir, self->buf, SMALL_BUF, self->names, &self->n), 3);
	ASSERT_EQ(count(self->names, self->n, TUN_NAME), 1);

	/* closing the device unregisters its sysctls under RTNL */
	close(tun);
	ASSERT_EQ(access(TUN_PATH, F_OK), -1);

	while (list(self->dir, self->buf, sizeof(self->buf), self->names,
		    &self->n) > 0)
		;
	EXPECT_EQ(count(self->names, self->n, "all"), 1);
	EXPECT_EQ(count(self->names, self->n, "default"), 1);
	EXPECT_EQ(count(self->names, self->n, "lo"), 1);
}

TEST_HARNESS_MAIN
