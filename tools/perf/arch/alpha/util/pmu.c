// SPDX-License-Identifier: GPL-2.0

#include "../../../util/pmu.h"
#include "mem-events.h"

void perf_pmu__arch_init(struct perf_pmu *pmu)
{
	/* ProfileMe is only on the EV67 and later. */
	if (pmu->is_core && perf_pmu__has_format(pmu, "profileme"))
		pmu->mem_events = perf_mem_events_alpha;
}
