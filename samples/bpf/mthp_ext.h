/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __MTHP_EXT_H__
#define __MTHP_EXT_H__

#define CGROUP_NAME_LEN 128
#define PMD_ORDER	9
#define min(a, b)	((a) < (b) ? a : b)
#define FROM_MB(s)	(s * 1024UL * 1024UL)
#define TO_MB(s)	(s / 1024UL / 1024UL)

struct config_local {
	unsigned long threshold;
	unsigned long interval;
	unsigned int  init_order;
	unsigned int  min_mem;
	bool fixed;
	bool debug;
};

struct alert_event {
	unsigned long long prev_stall;
	unsigned long long curr_stall;
	unsigned long long delta;
	unsigned long mem;
	unsigned int  order;
	char name[CGROUP_NAME_LEN];
};

#endif /* __MTHP_EXT_H__ */
