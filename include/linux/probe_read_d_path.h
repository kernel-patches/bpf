// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2024 Google LLC.
 */

#ifndef _LINUX_PROBE_READ_D_PATH_H
#define _LINUX_PROBE_READ_D_PATH_H

#include <linux/path.h>

extern char *probe_read_d_path(const struct path *path, char *buf, int buflen);

#endif /* _LINUX_PROBE_READ_D_PATH_H */
