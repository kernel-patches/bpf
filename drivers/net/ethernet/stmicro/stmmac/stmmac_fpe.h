/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2024 Furong Xu <0x1207@gmail.com>
 * stmmac FPE(802.3 Qbu) handling
 */
#include "stmmac.h"

#define STMMAC_FPE_MM_MAX_VERIFY_RETRIES	3
#define STMMAC_FPE_MM_MAX_VERIFY_TIME_MS	128

#define GMAC5_MAC_FPE_CTRL_STS		0x00000234
#define XGMAC_MAC_FPE_CTRL_STS		0x00000280

#define GMAC5_MTL_FPE_CTRL_STS		0x00000c90
#define XGMAC_MTL_FPE_CTRL_STS		0x00001090
/* Preemption Classification */
#define FPE_MTL_PREEMPTION_CLASS	GENMASK(15, 8)
/* Additional Fragment Size of preempted frames */
#define FPE_MTL_ADD_FRAG_SZ		GENMASK(1, 0)

#define STMMAC_MAC_FPE_CTRL_STS_TRSP	BIT(19)
#define STMMAC_MAC_FPE_CTRL_STS_TVER	BIT(18)
#define STMMAC_MAC_FPE_CTRL_STS_RRSP	BIT(17)
#define STMMAC_MAC_FPE_CTRL_STS_RVER	BIT(16)
#define STMMAC_MAC_FPE_CTRL_STS_SRSP	BIT(2)
#define STMMAC_MAC_FPE_CTRL_STS_SVER	BIT(1)
#define STMMAC_MAC_FPE_CTRL_STS_EFPE	BIT(0)

/* FPE link-partner hand-shaking mPacket type */
enum stmmac_mpacket_type {
	MPACKET_VERIFY = 0,
	MPACKET_RESPONSE = 1,
};

void stmmac_fpe_link_state_handle(struct stmmac_priv *priv, bool is_up);
void stmmac_fpe_event_status(struct stmmac_priv *priv, int status);
void stmmac_fpe_init(struct stmmac_priv *priv);
void stmmac_fpe_apply(struct stmmac_priv *priv);
