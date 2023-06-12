/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright (C) 2023 Yafang Shao <laoar.shao@gmail.com> */

#include <linux/perf_event.h>

const char *perf_type_str(enum perf_type_id t);
const char *perf_hw_str(enum perf_hw_id t);
const char *perf_hw_cache_str(enum perf_hw_cache_id t);
const char *perf_hw_cache_op_str(enum perf_hw_cache_op_id t);
const char *perf_hw_cache_op_result_str(enum perf_hw_cache_op_result_id t);
const char *perf_sw_str(enum perf_sw_ids t);
