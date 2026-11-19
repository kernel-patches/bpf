// SPDX-License-Identifier: GPL-2.0-only
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <libvfio.h>

/* Large enough to hold any single /dev/kmsg record. */
#define KMSG_RECORD_MAX 8192

/* Limit how much is printed if the kernel logs a flood of warnings. */
#define KMSG_PRINT_MAX 512

/*
 * Limit how many records are read, so that this terminates even if other
 * processes are logging messages faster than they can be read.
 */
#define KMSG_READ_MAX 65536

/**
 * kmsg_open() - Open /dev/kmsg to read kernel messages logged from now on
 *
 * Open /dev/kmsg positioned after the last message currently in the kernel
 * log, so that kmsg_print_warnings() only prints messages logged after this
 * call. If /dev/kmsg cannot be opened, e.g. because the caller is not allowed
 * to read the kernel log, print a message saying that kernel warnings will not
 * be printed.
 *
 * Return: A file descriptor on success, or a negative errno on failure.
 */
int kmsg_open(void)
{
	int fd, ret;

	fd = open("/dev/kmsg", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) {
		ret = -errno;
		goto out_err;
	}

	if (lseek(fd, 0, SEEK_END) < 0) {
		ret = -errno;
		close(fd);
		goto out_err;
	}

	return fd;

out_err:
	fprintf(stderr,
		"# kmsg: Failed to open /dev/kmsg (%s), kernel warnings will not be printed\n",
		strerror(-ret));
	return ret;
}

/**
 * kmsg_print_warnings() - Print kernel warnings logged since kmsg_open()
 * @fd: File descriptor returned by kmsg_open().
 *
 * Print all kernel messages at KERN_WARNING or higher priority that have been
 * logged since kmsg_open() (or since the last call to this function), e.g. to
 * provide context for a test failure caused by a kernel warning.
 *
 * Messages may be missing if the kernel log wrapped since they were logged,
 * and output is limited if the kernel logged a large number of messages. A
 * note is printed in either case.
 */
void kmsg_print_warnings(int fd)
{
	char buf[KMSG_RECORD_MAX];
	bool truncated = true;
	bool lost = false;
	int printed = 0;
	int omitted = 0;
	int i;

	for (i = 0; i < KMSG_READ_MAX; i++) {
		char *text, *end;
		ssize_t len;
		int prio;

		len = read(fd, buf, sizeof(buf) - 1);
		if (len < 0 && errno == EPIPE) {
			/* Messages were overwritten before being read. */
			lost = true;
			continue;
		}

		/* Stop at EAGAIN (no more messages) or on any other error. */
		if (len <= 0) {
			truncated = false;
			break;
		}

		buf[len] = '\0';

		/*
		 * Each record is "<prio>,<seq>,<ts>,<flags>;<message>\n",
		 * optionally followed by " KEY=VALUE\n" lines. See
		 * Documentation/ABI/testing/dev-kmsg.
		 */
		text = strchr(buf, ';');
		if (!text || sscanf(buf, "%d,", &prio) != 1)
			continue;

		text++;
		end = strchr(text, '\n');
		if (end)
			*end = '\0';

		if (LOG_FAC(prio) != LOG_FAC(LOG_KERN) || LOG_PRI(prio) > LOG_WARNING)
			continue;

		if (printed < KMSG_PRINT_MAX) {
			fprintf(stderr, "# kmsg: %s\n", text);
			printed++;
		} else {
			omitted++;
		}
	}

	if (omitted)
		fprintf(stderr, "# kmsg: (%d more messages omitted)\n", omitted);

	if (lost)
		fprintf(stderr, "# kmsg: (some messages were lost, see the kernel log)\n");

	if (truncated)
		fprintf(stderr, "# kmsg: (stopped reading, see the kernel log)\n");
}
