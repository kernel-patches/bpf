/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IOU_TOOLS_COMMON_DEFS_H
#define IOU_TOOLS_COMMON_DEFS_H

#include <linux/types.h>
#include <linux/stddef.h>

struct ring_info {
	unsigned	cq_hdr_offset;
	unsigned	sq_hdr_offset;
	unsigned	cqes_offset;
	unsigned	sq_entries;
	unsigned	cq_entries;

	void		*region_uaddr;
	unsigned	region_size;
};

struct nops_state {
	unsigned	stat_nr_cqes;
	unsigned	stat_nr_sqes;
	int		result;
	int		reqs_inflight;
	int		reqs_left;
};

struct unreg_state {
	unsigned	times_invoked;
};

#endif /* IOU_TOOLS_COMMON_DEFS_H */
