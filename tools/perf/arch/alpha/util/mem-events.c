// SPDX-License-Identifier: GPL-2.0
#include "util/map_symbol.h"
#include "util/mem-events.h"
#include "mem-events.h"

#define E(t, n, s, l, a) { .tag = t, .name = n, .event_name = s, .ldlat = l, .aux_event = a }

/*
 * ProfileMe samples loads and stores alike, and reports DTB hits and misses
 * in the data source. A precise event would sample only retired
 * instructions, which leaves out the DTB misses, so set the profileme bit.
 */
struct perf_mem_event perf_mem_events_alpha[PERF_MEM_EVENTS__MAX] = {
	E(NULL,		NULL,			NULL,		false,	0),
	E(NULL,		NULL,			NULL,		false,	0),
	E("mem-ldst",	"%s/cycles,profileme/",	"cycles",	false,	0),
};
