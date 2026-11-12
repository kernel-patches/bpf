/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __RESOLVE_BTFIDS_FMODRET_SCAN_H
#define __RESOLVE_BTFIDS_FMODRET_SCAN_H

#include <stdint.h>

#include "image.h"

struct scan;

/* Return NULL, after a message, if the code of IMG cannot be read */
struct scan *scan_open(const struct image *img);
void scan_close(struct scan *scan);
/*
 * Find the constants which FUNC returns and whose low 32 bits are an error. Set
 * VALUES to what the return value register holds then, until the next call.
 * Return how many there are, or -EINVAL if the code cannot be decoded.
 */
int scan_func(struct scan *scan, const struct image_func *func, const int64_t **values);

#endif
