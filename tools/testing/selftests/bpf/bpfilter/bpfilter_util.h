/* SPDX-License-Identifier: GPL-2.0 */

#ifndef BPFILTER_UTIL_H
#define BPFILTER_UTIL_H

#include <linux/netfilter/x_tables.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>

static inline void init_entry_match(struct xt_entry_match *match,
				    uint16_t size, uint8_t revision,
				    const char *name)
{
	memset(match, 0, sizeof(*match));
	sprintf(match->u.user.name, "%s", name);
	match->u.user.match_size = size;
	match->u.user.revision = revision;
}

#endif // BPFILTER_UTIL_H
