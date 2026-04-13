// SPDX-License-Identifier: GPL-2.0
/*
 * Write in a pipe and wait.
 *
 * Used by layout1.umount_sandboxer from fs_test.c
 *
 * Copyright © 2024-2025 Microsoft Corporation
 */

#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
	int pipe_child, pipe_parent;
	char buf;

	/* The first two arguments must be the file descriptor numbers of pipes. */
	if (argc != 3 && argc != 4) {
		fprintf(stderr, "Wrong number of arguments (not two or three)\n");
		return 1;
	}

	pipe_child = atoi(argv[1]);
	pipe_parent = atoi(argv[2]);

	/* Signals that we are waiting. */
	if (write(pipe_child, ".", 1) != 1) {
		perror("Failed to write to first argument");
		return 1;
	}

	/* Waits for the parent do its test. */
	if (read(pipe_parent, &buf, 1) != 1) {
		perror("Failed to write to the second argument");
		return 1;
	}

	if (argc == 4) {
		const pid_t target_pid = atoi(argv[3]);

		if (!kill(target_pid, 0)) {
			fprintf(stderr, "Successfully sent a signal to the target");
			return 1;
		}
		if (errno != EPERM) {
			perror("Failed to send a signal to the target");
			return 1;
		}
	}

	return 0;
}
