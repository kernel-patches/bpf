/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Nebula Matrix Limited.
 */

#ifndef _NBL_HW_REG_H_
#define _NBL_HW_REG_H_

#include <linux/types.h>

#include "../nbl_include/nbl_def_channel.h"
#include "../nbl_include/nbl_def_hw.h"
#include "../nbl_include/nbl_def_common.h"
#include "../nbl_core.h"

#define NBL_MEMORY_BAR				0
#define NBL_MAILBOX_BAR				2
#define NBL_RDMA_NOTIFY_LEN			(8ULL << 10)
#define NBL_REG_NET_ONLY_LEN			(8ULL << 10)
#define NBL_HW_DUMMY_REG			0x1300904
/*
 * PCI MEMORY BAR total size: 64MiB.
 */
#define NBL_MEM_BAR_TOTAL_SIZE			(64ULL << 20)

struct nbl_hw_mgt {
	struct nbl_common_info *common;
	u8 __iomem *hw_addr;
	u8 __iomem *mailbox_bar_hw_addr;
	resource_size_t mailbox_bar_size;
	spinlock_t reg_lock; /* Protect reg access */
};

static inline u32 rd32(u8 __iomem *addr, u64 reg)
{
	return readl(addr + reg);
}

static inline void wr32(u8 __iomem *addr, u64 reg, u32 value)
{
	writel(value, addr + reg);
}

static inline void nbl_hw_wr32(struct nbl_hw_mgt *hw_mgt, u64 reg, u32 value)
{
	wr32(hw_mgt->hw_addr, reg, value);
}

static inline u32 nbl_hw_rd32(struct nbl_hw_mgt *hw_mgt, u64 reg)
{
	return rd32(hw_mgt->hw_addr, reg);
}

static inline void nbl_mbx_wr32(struct nbl_hw_mgt *hw_mgt, u64 reg, u32 value)
{
	writel(value, hw_mgt->mailbox_bar_hw_addr + reg);
}

/*
 * Only call this when has_ctrl=true, which maps enough space
 * (bar_len - 8192) to cover NBL_HW_DUMMY_REG (0x1300904).
 * The flow/design guarantees this is only called in the
 * has_ctrl path.
 */
static inline void nbl_flush_writes(struct nbl_hw_mgt *hw_mgt)
{
	nbl_hw_rd32(hw_mgt, NBL_HW_DUMMY_REG);
}

static inline u32 nbl_mbx_rd32(struct nbl_hw_mgt *hw_mgt, u64 reg)
{
	return readl(hw_mgt->mailbox_bar_hw_addr + reg);
}

#endif
