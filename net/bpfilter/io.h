/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021 Telegram FZ-LLC
 */

#ifndef NET_BPFILTER_IO_H
#define NET_BPFILTER_IO_H

#include <stddef.h>
#include <sys/types.h>

int read_exact(int fd, void *buffer, size_t count);
int write_exact(int fd, const void *buffer, size_t count);

int pvm_read(pid_t pid, void *to, const void *from, size_t count);
int pvm_write(pid_t pid, void *to, const void *from, size_t count);

#endif // NET_BPFILTER_IO_H
