/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) Yikai Lin <yikai.lin@vivo.com>
 */

#ifndef _CPUIDLE_COMMON_H
#define _CPUIDLE_COMMON_H

int bpf_cpuidle_ext_gov_update_rating(unsigned int rating) __ksym __weak;
s64 bpf_cpuidle_ext_gov_latency_req(unsigned int cpu) __ksym __weak;
s64 bpf_tick_nohz_get_sleep_length(void) __ksym __weak;

#endif /* _CPUIDLE_COMMON_H */
