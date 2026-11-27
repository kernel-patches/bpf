/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2017 Chen-Yu Tsai. All rights reserved.
 */

#ifndef _CCU_SDM_H
#define _CCU_SDM_H

#include <linux/clk-provider.h>

#include "ccu_common.h"

struct ccu_sdm_setting {
	unsigned long	rate;

	/*
	 * XXX We don't know what the step and bottom register fields
	 * mean. Just copy the whole register value from the vendor
	 * kernel for now.
	 */
	u32		pattern;

	/*
	 * M and N factors here should be the values used in
	 * calculation, not the raw values written to registers
	 */
	u32		m;
	u32		n;
};

struct ccu_sdm_internal {
	struct ccu_sdm_setting	*table;
	u32		table_size;
	/* early SoCs don't have the SDM enable bit in the PLL register */
	u32		enable;
	/* second enable bit in pattern0 register */
	u32		pat0_enable;
	u16		pat0_reg;
	/* on some platforms, the sdm enable bit in pattern1 register */
	u32		pat1_enable;
	u16		pat1_reg;
};

#define _SUNXI_CCU_SDM_DUAL_PAT(_table, _enable, _pat0, _pat0_enable, _pat1, _pat1_enable) \
	{								\
		.table			= _table,			\
		.table_size		= ARRAY_SIZE(_table),		\
		.enable			= _enable,			\
		.pat0_enable		= _pat0_enable,			\
		.pat0_reg		= _pat0,			\
		.pat1_enable		= _pat1_enable,			\
		.pat1_reg		= _pat1,			\
	}

#define _SUNXI_CCU_SDM(_table, _enable, _pat0, _pat0_enable)	\
	_SUNXI_CCU_SDM_DUAL_PAT(_table, _enable, _pat0, _pat0_enable, 0, 0)

bool ccu_sdm_helper_is_enabled(struct ccu_common *common,
			       struct ccu_sdm_internal *sdm);
void ccu_sdm_helper_enable(struct ccu_common *common,
			   struct ccu_sdm_internal *sdm,
			   unsigned long rate);
void ccu_sdm_helper_disable(struct ccu_common *common,
			    struct ccu_sdm_internal *sdm);

bool ccu_sdm_helper_has_rate(struct ccu_common *common,
			     struct ccu_sdm_internal *sdm,
			     unsigned long rate);

unsigned long ccu_sdm_helper_read_rate(struct ccu_common *common,
				       struct ccu_sdm_internal *sdm,
				       u32 m, u32 n);

int ccu_sdm_helper_get_factors(struct ccu_common *common,
			       struct ccu_sdm_internal *sdm,
			       unsigned long rate,
			       unsigned long *m, unsigned long *n);

#endif
