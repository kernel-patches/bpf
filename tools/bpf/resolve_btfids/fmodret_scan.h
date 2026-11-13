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
 * FUNC takes pointers in the parameters POINTERS: bit N is parameter N. If EFFECT,
 * a call of it changes the objects which they point to.
 */
void scan_set_proto(struct scan *scan, const struct image_func *func, unsigned int pointers,
		    bool effect);
/*
 * Find the constants which FUNC returns and whose low 32 bits are an error. Set
 * VALUES to what the return value register holds then, until the next call.
 * Leave out a constant if each path from the entry to its return has an effect
 * on an object which FUNC gets a pointer to, see text_flow.h.
 * Return how many there are, or -EINVAL if the code cannot be decoded.
 */
int scan_func(struct scan *scan, const struct image_func *func, const int64_t **values);

#endif
