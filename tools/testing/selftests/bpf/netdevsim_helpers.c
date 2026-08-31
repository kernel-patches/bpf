// SPDX-License-Identifier: GPL-2.0

#include <errno.h>
#include <fcntl.h>
#include <linux/rtnetlink.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "netdevsim_helpers.h"

static int echo(const char *path, const char *fmt, ...)
{
	char buf[64];
	va_list ap;
	int fd, len, err = 0;

	va_start(ap, fmt);
	len = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	fd = open(path, O_WRONLY);
	if (fd < 0)
		return -errno;
	if (write(fd, buf, len) != len)
		err = -errno;
	close(fd);

	return err;
}

void netdevsim_destroy(unsigned int id)
{
	echo("/sys/bus/netdevsim/del_device", "%u", id);
}

static int create_new_device(void)
{
	unsigned int id;
	int err;

	/* if 10K is not enough, then something is clearly not right */
	for (id = 0; id < 10000; id++) {
		err = echo("/sys/bus/netdevsim/new_device", "%u", id);
		if (!err)
			return id;
		if (err != -ENOSPC)
			return err;
	}

	return -ENOSPC;
}

static int open_link_socket(void)
{
	struct sockaddr_nl addr = {
		.nl_family = AF_NETLINK,
		.nl_groups = RTMGRP_LINK,
	};
	int fd;

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (fd < 0)
		return -errno;
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr))) {
		int err = -errno;

		close(fd);
		return err;
	}

	return fd;
}

static int remaining_timeout_ms(const struct timespec *deadline)
{
	struct timespec now;
	long long remaining;

	if (clock_gettime(CLOCK_MONOTONIC, &now))
		return -errno;

	remaining = (deadline->tv_sec - now.tv_sec) * 1000 +
		    (deadline->tv_nsec - now.tv_nsec) / 1000000;

	return remaining > 0 ? remaining : 0;
}

static int recv_device_ifindex(int fd, unsigned int id, unsigned int *ifindex)
{
	char parent_name[32], buf[16 * 1024];
	struct pollfd pfd = {
		.fd = fd,
		.events = POLLIN,
	};
	struct timespec deadline;
	struct nlmsghdr *nlh;
	int len, ret, timeout;

	snprintf(parent_name, sizeof(parent_name), "netdevsim%u", id);
	if (clock_gettime(CLOCK_MONOTONIC, &deadline))
		return -errno;
	deadline.tv_sec += 5;

	for (timeout = remaining_timeout_ms(&deadline); timeout > 0;
	     timeout = remaining_timeout_ms(&deadline)) {
		ret = poll(&pfd, 1, timeout);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (!ret)
			return -ETIMEDOUT;
		if (!(pfd.revents & POLLIN))
			return -EIO;

		len = recv(fd, buf, sizeof(buf), 0);
		if (len < 0)
			return -errno;

		for (nlh = (struct nlmsghdr *)buf; NLMSG_OK(nlh, len);
		     nlh = NLMSG_NEXT(nlh, len)) {
			struct ifinfomsg *ifm;
			struct rtattr *attr;
			int attr_len;

			if (nlh->nlmsg_type != RTM_NEWLINK)
				continue;

			ifm = NLMSG_DATA(nlh);
			attr = IFLA_RTA(ifm);
			attr_len = IFLA_PAYLOAD(nlh);
			for (; RTA_OK(attr, attr_len);
			     attr = RTA_NEXT(attr, attr_len)) {
				if (attr->rta_type != IFLA_PARENT_DEV_NAME)
					continue;
				if (strcmp(RTA_DATA(attr), parent_name))
					continue;

				*ifindex = ifm->ifi_index;
				return 0;
			}
		}
	}

	return timeout < 0 ? timeout : -ETIMEDOUT;
}

int netdevsim_create(unsigned int *ifindex)
{
	int fd, id, err;

	fd = open_link_socket();
	if (fd < 0)
		return fd;

	id = create_new_device();
	if (id < 0) {
		close(fd);
		return id;
	}

	err = recv_device_ifindex(fd, id, ifindex);
	close(fd);
	if (err) {
		netdevsim_destroy(id);
		return err;
	}

	return id;
}
