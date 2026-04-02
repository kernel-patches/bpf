// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

static int check_read(const char *path)
{
	int fd;
	char byte;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return errno;
	if (read(fd, &byte, 1) < 0) {
		int err = errno;

		close(fd);
		return err;
	}
	close(fd);
	return 0;
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		fprintf(stderr, "missing mode\n");
		return 2;
	}

	if (!strcmp(argv[1], "nnp"))
		return prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1 ? 0 : 1;

	if (!strcmp(argv[1], "read")) {
		if (argc != 3) {
			fprintf(stderr, "missing path\n");
			return 2;
		}
		return check_read(argv[2]);
	}

	fprintf(stderr, "unknown mode\n");
	return 2;
}
