// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021 Telegram FZ-LLC
 */

#define _GNU_SOURCE

#include "io.h"

#include <errno.h>
#include <sys/uio.h>
#include <unistd.h>

#define do_exact(fd, op, buffer, count)                                                            \
	({                                                                                         \
		size_t total = 0;                                                                  \
		int err = 0;                                                                       \
												   \
		do {                                                                               \
			const ssize_t part = op(fd, (buffer) + total, (count) - total);            \
			if (part > 0) {                                                            \
				total += part;                                                     \
			} else if (part == 0 && (count) > 0) {                                     \
				err = -EIO;                                                        \
				break;                                                             \
			} else if (part == -1) {                                                   \
				if (errno == EINTR)                                                \
					continue;                                                  \
				err = -errno;                                                      \
				break;                                                             \
			}                                                                          \
		} while (total < (count));                                                         \
												   \
		err;                                                                               \
	})

int read_exact(int fd, void *buffer, size_t count)
{
	return do_exact(fd, read, buffer, count);
}

int write_exact(int fd, const void *buffer, size_t count)
{
	return do_exact(fd, write, buffer, count);
}

int pvm_read(pid_t pid, void *to, const void *from, size_t count)
{
	const struct iovec r_iov = { .iov_base = (void *)from, .iov_len = count };
	const struct iovec l_iov = { .iov_base = to, .iov_len = count };
	size_t total_bytes;

	total_bytes = process_vm_readv(pid, &l_iov, 1, &r_iov, 1, 0);
	if (total_bytes == -1)
		return -errno;

	if (total_bytes != count)
		return -EFAULT;

	return 0;
}

int pvm_write(pid_t pid, void *to, const void *from, size_t count)
{
	const struct iovec l_iov = { .iov_base = (void *)from, .iov_len = count };
	const struct iovec r_iov = { .iov_base = to, .iov_len = count };
	size_t total_bytes;

	total_bytes = process_vm_writev(pid, &l_iov, 1, &r_iov, 1, 0);
	if (total_bytes == -1)
		return -errno;

	if (total_bytes != count)
		return -EFAULT;

	return 0;
}
