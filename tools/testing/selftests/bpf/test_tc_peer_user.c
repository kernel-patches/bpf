// SPDX-License-Identifier: GPL-2.0

/*
 * Networking across two network namespaces based on TUN/TAP.
 * Like veth, but slow and L3. Used for testing BPF redirect_peer
 * from L3 to L2 veth device.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/limits.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int tun_alloc(char *name) {
	struct ifreq ifr;
	int fd, err;
	char cmd[512];

	if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
		return -1;

	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	if (*name)
		strncpy(ifr.ifr_name, name, IFNAMSIZ);

	if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
		close(fd);
		return err;
	}

	snprintf(cmd, sizeof(cmd), "ip link set dev %s up", name);
	system(cmd);

	return fd;
}

#define MAX(a, b) ((a) > (b) ? (a) : (b))

enum {
	SRC_TO_TARGET = 0,
	TARGET_TO_SRC = 1,
};

void setns_by_name(char *name) {
	int nsfd;
	char nspath[PATH_MAX];

        snprintf(nspath, sizeof(nspath), "%s/%s", "/var/run/netns", name);
        nsfd = open(nspath, O_RDONLY | O_CLOEXEC);
        if (nsfd < 0) {
		fprintf(stderr, "failed to open net namespace %s: %s\n", name, strerror(errno));
		exit(1);
        }
	setns(nsfd, CLONE_NEWNET);
	close(nsfd);
}

int main(int argc, char **argv) {
	char *src_ns, *src_tun, *target_ns, *target_tun;
	int srcfd, targetfd;

	if (argc != 5) {
		fprintf(stderr, "usage: %s <source namespace> <source tun device name> <target namespace> <target tun device name>\n", argv[0]);
		return 1;
	}

	src_ns = argv[1];
	src_tun = argv[2];
	target_ns = argv[3];
	target_tun = argv[4];

	setns_by_name(src_ns);
	srcfd = tun_alloc(src_tun);
	if (srcfd < 0) {
		fprintf(stderr, "failed to allocate tun device\n");
		return 1;
	}

	setns_by_name(target_ns); 
	targetfd = tun_alloc(target_tun);
	if (srcfd < 0) {
		fprintf(stderr, "failed to allocate tun device\n");
		return 1;
	}

	fd_set rfds, wfds;
	FD_ZERO(&rfds);
	FD_ZERO(&wfds);

	for (;;) {
	        char buf[4096];
	        int direction, nread, nwrite;
		FD_SET(srcfd, &rfds);
		FD_SET(targetfd, &rfds);

		if (select(1 + MAX(srcfd, targetfd), &rfds, NULL, NULL, NULL) < 0) {
		       fprintf(stderr, "select failed: %s\n", strerror(errno));
		       return 1;
	        }

	        direction = FD_ISSET(srcfd, &rfds) ? SRC_TO_TARGET : TARGET_TO_SRC;

	        nread = read(direction == SRC_TO_TARGET ? srcfd : targetfd, buf, sizeof(buf));
	        if (nread < 0) {
		       fprintf(stderr, "read failed: %s\n", strerror(errno));
		       return 1;
	        }

	        nwrite = write(direction == SRC_TO_TARGET ? targetfd : srcfd, buf, nread);
	        if (nwrite != nread) {
		       fprintf(stderr, "write failed: %s\n", strerror(errno));
		       return 1;
	        }
	}
}
