/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 KylinSoft Corporation.
 * Copyright (c) 2026 Kaitao Cheng <chengkaitao@kylinos.cn>
 */
#ifndef __UFQ_SIMPLE_STAT_H
#define __UFQ_SIMPLE_STAT_H

enum ufq_simp_stat_index {
	UFQ_SIMP_INSERT_CNT,
	UFQ_SIMP_INSERT_SIZE,
	UFQ_SIMP_DISPATCH_CNT,
	UFQ_SIMP_DISPATCH_SIZE,
	UFQ_SIMP_RQMERGE_CNT,
	UFQ_SIMP_RQMERGE_SIZE,
	UFQ_SIMP_BIOMERGE_CNT,
	UFQ_SIMP_BIOMERGE_SIZE,
	UFQ_SIMP_FINISH_CNT,
	UFQ_SIMP_FINISH_SIZE,
	UFQ_SIMP_STAT_MAX,
};

#endif /* __UFQ_SIMPLE_STAT_H */
