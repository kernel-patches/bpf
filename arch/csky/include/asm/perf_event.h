/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __ASM_CSKY_PERF_EVENT_H
#define __ASM_CSKY_PERF_EVENT_H

#include <abi/regdef.h>

#define perf_arch_fetch_caller_regs(regs, __ip) { \
	(regs)->pc = (__ip); \
	regs_fp(regs) = (unsigned long) __builtin_frame_address(0); \
	asm volatile("mov %0, sp\n":"=r"((regs)->usp)); \
}

struct perf_event;
struct platform_device;
struct of_device_id;

uint64_t csky_pmu_read_cc(void);
int csky_pmu_event_set_period(struct perf_event *event);
int init_hw_perf_events(void);
int csky_pmu_device_probe(struct platform_device *pdev,
			  const struct of_device_id *of_table);

#endif /* __ASM_PERF_EVENT_ELF_H */
