// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <sched.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#define NSIO    0xb7
#define NS_GET_COOKIE   _IO(NSIO, 0x5)

#define pr_err(fmt, ...) \
		({ \
			fprintf(stderr, "%s:%d:" fmt ": %m\n", \
				__func__, __LINE__, ##__VA_ARGS__); \
			1; \
		})

int main(int argc, char *argvp[])
{
	uint64_t cookie1, cookie2;
	char path[128];
	int ns;

	snprintf(path, sizeof(path), "/proc/%d/ns/net", getpid());
	ns = open(path, O_RDONLY);
	if (ns < 0)
		return pr_err("Unable to open %s", path);

	if (ioctl(ns, NS_GET_COOKIE, &cookie1))
		return pr_err("Unable to get first namespace cookie");

	if (!cookie1)
		return pr_err("NS_GET_COOKIE returned zero first cookie");

	close(ns);
	if (unshare(CLONE_NEWNET))
		return pr_err("unshare");

	ns = open(path, O_RDONLY);
	if (ns < 0)
		return pr_err("Unable to open %s", path);

	if (ioctl(ns, NS_GET_COOKIE, &cookie2))
		return pr_err("Unable to get second namespace cookie");

	if (!cookie2)
		return pr_err("NS_GET_COOKIE returned zero second cookie");

	if (cookie1 == cookie2)
		return pr_err("NS_GET_COOKIE returned identical cookies for distinct ns");

	close(ns);
	return 0;
}
