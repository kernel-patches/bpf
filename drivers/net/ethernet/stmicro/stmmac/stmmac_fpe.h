/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2024 Furong Xu <0x1207@gmail.com>
 * stmmac FPE(802.3 Qbu) handling
 */
#include "stmmac.h"

#define STMMAC_FPE_MM_MAX_VERIFY_RETRIES	3
#define STMMAC_FPE_MM_MAX_VERIFY_TIME_MS	128

#define MAC_FPE_CTRL_STS		0x00000234
#define TRSP				BIT(19)
#define TVER				BIT(18)
#define RRSP				BIT(17)
#define RVER				BIT(16)
#define SRSP				BIT(2)
#define SVER				BIT(1)
#define EFPE				BIT(0)

#define MTL_FPE_CTRL_STS		0x00000c90
/* Preemption Classification */
#define DWMAC5_PREEMPTION_CLASS		GENMASK(15, 8)
/* Additional Fragment Size of preempted frames */
#define DWMAC5_ADD_FRAG_SZ		GENMASK(1, 0)

#define XGMAC_FPE_CTRL_STS		0x00000280
#define XGMAC_EFPE			BIT(0)

/* FPE link-partner hand-shaking mPacket type */
enum stmmac_mpacket_type {
	MPACKET_VERIFY = 0,
	MPACKET_RESPONSE = 1,
};

void stmmac_fpe_link_state_handle(struct stmmac_priv *priv, bool is_up);
void stmmac_fpe_event_status(struct stmmac_priv *priv, int status);
void stmmac_fpe_init(struct stmmac_priv *priv);
void stmmac_fpe_apply(struct stmmac_priv *priv);

void dwmac5_fpe_configure(void __iomem *ioaddr, struct stmmac_fpe_cfg *cfg,
			  u32 num_txq, u32 num_rxq,
			  bool tx_enable, bool pmac_enable);
void dwmac5_fpe_send_mpacket(void __iomem *ioaddr,
			     struct stmmac_fpe_cfg *cfg,
			     enum stmmac_mpacket_type type);
int dwmac5_fpe_irq_status(void __iomem *ioaddr, struct net_device *dev);
int dwmac5_fpe_get_add_frag_size(const void __iomem *ioaddr);
void dwmac5_fpe_set_add_frag_size(void __iomem *ioaddr, u32 add_frag_size);
int dwmac5_fpe_map_preemption_class(struct net_device *ndev,
				    struct netlink_ext_ack *extack, u32 pclass);

void dwxgmac3_fpe_configure(void __iomem *ioaddr, struct stmmac_fpe_cfg *cfg,
			    u32 num_txq, u32 num_rxq,
			    bool tx_enable, bool pmac_enable);
