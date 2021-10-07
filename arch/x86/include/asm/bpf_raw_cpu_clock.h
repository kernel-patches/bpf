/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_BPF_RAW_CPU_CLOCK_H_
#define _ASM_X86_BPF_RAW_CPU_CLOCK_H_

static inline unsigned long long read_raw_cpu_clock(void)
{
	return rdtsc_ordered();
}

#endif /* _ASM_X86_BPF_RAW_CPU_CLOCK_H_ */
