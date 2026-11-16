// SPDX-License-Identifier: GPL-2.0
/*
 * A poll() or epoll on a /proc entry must wake up when the entry is removed,
 * and report the removed entry as an error. The channel file of a sunrpc
 * cache lives in /proc/net of a network namespace and goes away with it.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../kselftest_harness.h"

#define CHANNEL_FMT	"/proc/%d/net/rpc/auth.unix.ip/channel"
#define TIMEOUT_MS	10000

struct netns_child {
	pid_t pid;
	int go;		/* closing it lets the child exit, and its netns die */
};

struct poller {
	int fd;
	int done;
	int ret;
	short revents;
};

static int write_file(const char *path, const char *fmt, ...)
{
	char buf[64];
	va_list ap;
	int fd, len, ret;

	va_start(ap, fmt);
	len = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	ret = write(fd, buf, len) == len ? 0 : -1;
	close(fd);
	return ret;
}

/*
 * A child in a network namespace of its own, owned by a user namespace that
 * maps us to root, so that we may open the files in its /proc/net. The child
 * is the only thing that keeps the namespace alive.
 */
static int start_netns_child(struct netns_child *c)
{
	uid_t uid = getuid();
	gid_t gid = getgid();
	int ready[2], go[2];
	char ch = 'f';

	if (pipe2(ready, O_CLOEXEC) || pipe2(go, O_CLOEXEC))
		return -1;
	c->pid = fork();
	if (c->pid < 0)
		return -1;
	if (c->pid == 0) {
		close(ready[0]);
		close(go[1]);
		if (!unshare(CLONE_NEWUSER) &&
		    !write_file("/proc/self/setgroups", "deny") &&
		    !write_file("/proc/self/uid_map", "0 %d 1", uid) &&
		    !write_file("/proc/self/gid_map", "0 %d 1", gid) &&
		    !unshare(CLONE_NEWNET))
			ch = 'r';
		if (write(ready[1], &ch, 1) == 1 && ch == 'r')
			(void)!read(go[0], &ch, 1);
		_exit(0);
	}
	close(ready[1]);
	close(go[0]);
	c->go = go[1];
	if (read(ready[0], &ch, 1) != 1 || ch != 'r') {
		close(ready[0]);
		close(c->go);
		waitpid(c->pid, NULL, 0);
		errno = EPERM;
		return -1;
	}
	close(ready[0]);
	return 0;
}

static void end_netns_child(struct netns_child *c)
{
	close(c->go);
	waitpid(c->pid, NULL, 0);
}

static int open_channel(struct netns_child *c, char *path, size_t len)
{
	snprintf(path, len, CHANNEL_FMT, c->pid);
	return open(path, O_RDONLY | O_CLOEXEC);
}

static void *poll_thread(void *arg)
{
	struct poller *p = arg;
	struct pollfd pfd = { .fd = p->fd, .events = POLLPRI };
	ssize_t ret;

	p->ret = poll(&pfd, 1, TIMEOUT_MS);
	p->revents = pfd.revents;
	ret = write(p->done, "x", 1);
	return (void *)ret;
}

TEST(poll_wakes_on_removal)
{
	struct netns_child c;
	struct poller p = {};
	struct pollfd pfd;
	char path[64], buf[16];
	pthread_t pt;
	int done[2];

	if (start_netns_child(&c))
		SKIP(return, "network namespace: %s", strerror(errno));
	p.fd = open_channel(&c, path, sizeof(path));
	if (p.fd < 0)
		SKIP(return, "%s: %s", path, strerror(errno));

	/* A fresh channel has nothing to read and no error. */
	pfd = (struct pollfd){ .fd = p.fd, .events = POLLIN | POLLPRI };
	ASSERT_EQ(poll(&pfd, 1, 0), 0);

	ASSERT_EQ(pipe2(done, O_CLOEXEC), 0);
	p.done = done[1];
	ASSERT_EQ(pthread_create(&pt, NULL, poll_thread, &p), 0);

	/* The poller sleeps on the entry, now its namespace goes away. */
	end_netns_child(&c);
	pfd = (struct pollfd){ .fd = done[0], .events = POLLIN };
	EXPECT_EQ(poll(&pfd, 1, TIMEOUT_MS), 1) {
		TH_LOG("removing %s didn't wake its poller", path);
	}
	ASSERT_EQ(pthread_join(pt, NULL), 0);
	EXPECT_EQ(p.ret, 1);
	EXPECT_EQ(p.revents & (POLLERR | POLLPRI), POLLERR | POLLPRI);

	/* The removed entry stays an error, and there is nothing to read. */
	pfd = (struct pollfd){ .fd = p.fd, .events = POLLIN };
	EXPECT_EQ(poll(&pfd, 1, 0), 1);
	EXPECT_TRUE(pfd.revents & POLLERR);
	EXPECT_EQ(read(p.fd, buf, sizeof(buf)), -1);
	EXPECT_EQ(errno, EIO);
}

TEST(epoll_wakes_on_removal)
{
	struct epoll_event ev = { .events = EPOLLPRI };
	struct netns_child c;
	char path[64];
	int fd, epfd;

	if (start_netns_child(&c))
		SKIP(return, "network namespace: %s", strerror(errno));
	fd = open_channel(&c, path, sizeof(path));
	if (fd < 0)
		SKIP(return, "%s: %s", path, strerror(errno));

	epfd = epoll_create1(EPOLL_CLOEXEC);
	ASSERT_GE(epfd, 0);
	ASSERT_EQ(epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev), 0);
	ASSERT_EQ(epoll_wait(epfd, &ev, 1, 0), 0);

	/* The item sits on the entry's queue, now its namespace goes away. */
	end_netns_child(&c);
	EXPECT_EQ(epoll_wait(epfd, &ev, 1, TIMEOUT_MS), 1) {
		TH_LOG("removing %s didn't wake epoll", path);
	}
	EXPECT_EQ(ev.events & (EPOLLERR | EPOLLPRI), EPOLLERR | EPOLLPRI);
}

TEST_HARNESS_MAIN
