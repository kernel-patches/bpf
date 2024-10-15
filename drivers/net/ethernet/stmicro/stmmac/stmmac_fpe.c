// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024 Furong Xu <0x1207@gmail.com>
 * stmmac FPE(802.3 Qbu) handling
 */
#include "stmmac.h"
#include "stmmac_fpe.h"
#include "dwmac4.h"
#include "dwmac5.h"
#include "dwxgmac2.h"

void stmmac_fpe_link_state_handle(struct stmmac_priv *priv, bool is_up)
{
	struct stmmac_fpe_cfg *fpe_cfg = &priv->fpe_cfg;
	unsigned long flags;

	timer_shutdown_sync(&fpe_cfg->verify_timer);

	spin_lock_irqsave(&fpe_cfg->lock, flags);

	if (is_up && fpe_cfg->pmac_enabled) {
		/* VERIFY process requires pmac enabled when NIC comes up */
		stmmac_fpe_configure(priv, priv->ioaddr, fpe_cfg,
				     priv->plat->tx_queues_to_use,
				     priv->plat->rx_queues_to_use,
				     false, true);

		/* New link => maybe new partner => new verification process */
		stmmac_fpe_apply(priv);
	} else {
		/* No link => turn off EFPE */
		stmmac_fpe_configure(priv, priv->ioaddr, fpe_cfg,
				     priv->plat->tx_queues_to_use,
				     priv->plat->rx_queues_to_use,
				     false, false);
	}

	spin_unlock_irqrestore(&fpe_cfg->lock, flags);
}

void stmmac_fpe_event_status(struct stmmac_priv *priv, int status)
{
	struct stmmac_fpe_cfg *fpe_cfg = &priv->fpe_cfg;

	/* This is interrupt context, just spin_lock() */
	spin_lock(&fpe_cfg->lock);

	if (!fpe_cfg->pmac_enabled || status == FPE_EVENT_UNKNOWN)
		goto unlock_out;

	/* LP has sent verify mPacket */
	if ((status & FPE_EVENT_RVER) == FPE_EVENT_RVER)
		stmmac_fpe_send_mpacket(priv, priv->ioaddr, fpe_cfg,
					MPACKET_RESPONSE);

	/* Local has sent verify mPacket */
	if ((status & FPE_EVENT_TVER) == FPE_EVENT_TVER &&
	    fpe_cfg->status != ETHTOOL_MM_VERIFY_STATUS_SUCCEEDED)
		fpe_cfg->status = ETHTOOL_MM_VERIFY_STATUS_VERIFYING;

	/* LP has sent response mPacket */
	if ((status & FPE_EVENT_RRSP) == FPE_EVENT_RRSP &&
	    fpe_cfg->status == ETHTOOL_MM_VERIFY_STATUS_VERIFYING)
		fpe_cfg->status = ETHTOOL_MM_VERIFY_STATUS_SUCCEEDED;

unlock_out:
	spin_unlock(&fpe_cfg->lock);
}

/**
 * stmmac_fpe_verify_timer - Timer for MAC Merge verification
 * @t:  timer_list struct containing private info
 *
 * Verify the MAC Merge capability in the local TX direction, by
 * transmitting Verify mPackets up to 3 times. Wait until link
 * partner responds with a Response mPacket, otherwise fail.
 */
static void stmmac_fpe_verify_timer(struct timer_list *t)
{
	struct stmmac_fpe_cfg *fpe_cfg = from_timer(fpe_cfg, t, verify_timer);
	struct stmmac_priv *priv = container_of(fpe_cfg, struct stmmac_priv,
						fpe_cfg);
	unsigned long flags;
	bool rearm = false;

	spin_lock_irqsave(&fpe_cfg->lock, flags);

	switch (fpe_cfg->status) {
	case ETHTOOL_MM_VERIFY_STATUS_INITIAL:
	case ETHTOOL_MM_VERIFY_STATUS_VERIFYING:
		if (fpe_cfg->verify_retries != 0) {
			stmmac_fpe_send_mpacket(priv, priv->ioaddr,
						fpe_cfg, MPACKET_VERIFY);
			rearm = true;
		} else {
			fpe_cfg->status = ETHTOOL_MM_VERIFY_STATUS_FAILED;
		}

		fpe_cfg->verify_retries--;
		break;

	case ETHTOOL_MM_VERIFY_STATUS_SUCCEEDED:
		stmmac_fpe_configure(priv, priv->ioaddr, fpe_cfg,
				     priv->plat->tx_queues_to_use,
				     priv->plat->rx_queues_to_use,
				     true, true);
		break;

	default:
		break;
	}

	if (rearm) {
		mod_timer(&fpe_cfg->verify_timer,
			  jiffies + msecs_to_jiffies(fpe_cfg->verify_time));
	}

	spin_unlock_irqrestore(&fpe_cfg->lock, flags);
}

static void stmmac_fpe_verify_timer_arm(struct stmmac_fpe_cfg *fpe_cfg)
{
	if (fpe_cfg->pmac_enabled && fpe_cfg->tx_enabled &&
	    fpe_cfg->verify_enabled &&
	    fpe_cfg->status != ETHTOOL_MM_VERIFY_STATUS_FAILED &&
	    fpe_cfg->status != ETHTOOL_MM_VERIFY_STATUS_SUCCEEDED) {
		timer_setup(&fpe_cfg->verify_timer, stmmac_fpe_verify_timer, 0);
		mod_timer(&fpe_cfg->verify_timer, jiffies);
	}
}

void stmmac_fpe_init(struct stmmac_priv *priv)
{
	priv->fpe_cfg.verify_retries = STMMAC_FPE_MM_MAX_VERIFY_RETRIES;
	priv->fpe_cfg.verify_time = STMMAC_FPE_MM_MAX_VERIFY_TIME_MS;
	priv->fpe_cfg.status = ETHTOOL_MM_VERIFY_STATUS_DISABLED;
	timer_setup(&priv->fpe_cfg.verify_timer, stmmac_fpe_verify_timer, 0);
	spin_lock_init(&priv->fpe_cfg.lock);
}

void stmmac_fpe_apply(struct stmmac_priv *priv)
{
	struct stmmac_fpe_cfg *fpe_cfg = &priv->fpe_cfg;

	/* If verification is disabled, configure FPE right away.
	 * Otherwise let the timer code do it.
	 */
	if (!fpe_cfg->verify_enabled) {
		stmmac_fpe_configure(priv, priv->ioaddr, fpe_cfg,
				     priv->plat->tx_queues_to_use,
				     priv->plat->rx_queues_to_use,
				     fpe_cfg->tx_enabled,
				     fpe_cfg->pmac_enabled);
	} else {
		fpe_cfg->status = ETHTOOL_MM_VERIFY_STATUS_INITIAL;
		fpe_cfg->verify_retries = STMMAC_FPE_MM_MAX_VERIFY_RETRIES;

		if (netif_running(priv->dev))
			stmmac_fpe_verify_timer_arm(fpe_cfg);
	}
}

static void common_fpe_configure(void __iomem *ioaddr,
				 struct stmmac_fpe_cfg *cfg, u32 rxq,
				 bool tx_enable, bool pmac_enable,
				 u32 rxq_addr, u32 fprq_mask, u32 fprq_shift,
				 u32 mac_fpe_addr, u32 int_en_addr,
				 u32 int_en_bit)
{
	u32 value;

	if (tx_enable) {
		cfg->fpe_csr = STMMAC_MAC_FPE_CTRL_STS_EFPE;
		value = readl(ioaddr + rxq_addr);
		value &= ~fprq_mask;
		value |= (rxq - 1) << fprq_shift;
		writel(value, ioaddr + rxq_addr);
	} else {
		cfg->fpe_csr = 0;
	}
	writel(cfg->fpe_csr, ioaddr + mac_fpe_addr);

	value = readl(ioaddr + int_en_addr);

	if (pmac_enable) {
		if (!(value & int_en_bit)) {
			/* Dummy read to clear any pending masked interrupts */
			readl(ioaddr + mac_fpe_addr);

			value |= int_en_bit;
		}
	} else {
		value &= ~int_en_bit;
	}

	writel(value, ioaddr + int_en_addr);
}

static void dwmac5_fpe_configure(void __iomem *ioaddr,
				 struct stmmac_fpe_cfg *cfg,
				 u32 num_txq, u32 num_rxq,
				 bool tx_enable, bool pmac_enable)
{
	common_fpe_configure(ioaddr, cfg, num_rxq, tx_enable,
			     pmac_enable, GMAC_RXQ_CTRL1, GMAC_RXQCTRL_FPRQ,
			     GMAC_RXQCTRL_FPRQ_SHIFT, GMAC5_MAC_FPE_CTRL_STS,
			     GMAC_INT_EN, GMAC_INT_FPE_EN);
}

static int common_fpe_irq_status(void __iomem *ioaddr, struct net_device *dev)
{
	u32 value;
	int status;

	status = FPE_EVENT_UNKNOWN;

	/* Reads from the MAC_FPE_CTRL_STS register should only be performed
	 * here, since the status flags of MAC_FPE_CTRL_STS are "clear on read"
	 */
	value = readl(ioaddr);

	if (value & STMMAC_MAC_FPE_CTRL_STS_TRSP) {
		status |= FPE_EVENT_TRSP;
		netdev_dbg(dev, "FPE: Respond mPacket is transmitted\n");
	}

	if (value & STMMAC_MAC_FPE_CTRL_STS_TVER) {
		status |= FPE_EVENT_TVER;
		netdev_dbg(dev, "FPE: Verify mPacket is transmitted\n");
	}

	if (value & STMMAC_MAC_FPE_CTRL_STS_RRSP) {
		status |= FPE_EVENT_RRSP;
		netdev_dbg(dev, "FPE: Respond mPacket is received\n");
	}

	if (value & STMMAC_MAC_FPE_CTRL_STS_RVER) {
		status |= FPE_EVENT_RVER;
		netdev_dbg(dev, "FPE: Verify mPacket is received\n");
	}

	return status;
}

static int dwmac5_fpe_irq_status(void __iomem *ioaddr, struct net_device *dev)
{
	return common_fpe_irq_status(ioaddr + GMAC5_MAC_FPE_CTRL_STS, dev);
}

static void common_fpe_send_mpacket(void __iomem *ioaddr,
				    struct stmmac_fpe_cfg *cfg,
				    enum stmmac_mpacket_type type)
{
	u32 value = cfg->fpe_csr;

	if (type == MPACKET_VERIFY)
		value |= STMMAC_MAC_FPE_CTRL_STS_SVER;
	else if (type == MPACKET_RESPONSE)
		value |= STMMAC_MAC_FPE_CTRL_STS_SRSP;

	writel(value, ioaddr);
}

static void dwmac5_fpe_send_mpacket(void __iomem *ioaddr,
				    struct stmmac_fpe_cfg *cfg,
				    enum stmmac_mpacket_type type)
{
	common_fpe_send_mpacket(ioaddr + GMAC5_MAC_FPE_CTRL_STS, cfg, type);
}

static int dwmac5_fpe_get_add_frag_size(const void __iomem *ioaddr)
{
	return FIELD_GET(FPE_MTL_ADD_FRAG_SZ,
			 readl(ioaddr + GMAC5_MTL_FPE_CTRL_STS));
}

static void dwmac5_fpe_set_add_frag_size(void __iomem *ioaddr,
					 u32 add_frag_size)
{
	u32 value;

	value = readl(ioaddr + GMAC5_MTL_FPE_CTRL_STS);
	writel(u32_replace_bits(value, add_frag_size, FPE_MTL_ADD_FRAG_SZ),
	       ioaddr + GMAC5_MTL_FPE_CTRL_STS);
}

#define ALG_ERR_MSG "TX algorithm SP is not suitable for one-to-many mapping"
#define WEIGHT_ERR_MSG "TXQ weight %u differs across other TXQs in TC: [%u]"

static int dwmac5_fpe_map_preemption_class(struct net_device *ndev,
					   struct netlink_ext_ack *extack,
					   u32 pclass)
{
	u32 val, offset, count, queue_weight, preemptible_txqs = 0;
	struct stmmac_priv *priv = netdev_priv(ndev);
	u32 num_tc = ndev->num_tc;

	if (!pclass)
		goto update_mapping;

	/* DWMAC CORE4+ can not program TC:TXQ mapping to hardware.
	 *
	 * Synopsys Databook:
	 * "The number of Tx DMA channels is equal to the number of Tx queues,
	 * and is direct one-to-one mapping."
	 */
	for (u32 tc = 0; tc < num_tc; tc++) {
		count = ndev->tc_to_txq[tc].count;
		offset = ndev->tc_to_txq[tc].offset;

		if (pclass & BIT(tc))
			preemptible_txqs |= GENMASK(offset + count - 1, offset);

		/* This is 1:1 mapping, go to next TC */
		if (count == 1)
			continue;

		if (priv->plat->tx_sched_algorithm == MTL_TX_ALGORITHM_SP) {
			NL_SET_ERR_MSG_MOD(extack, ALG_ERR_MSG);
			return -EINVAL;
		}

		queue_weight = priv->plat->tx_queues_cfg[offset].weight;

		for (u32 i = 1; i < count; i++) {
			if (priv->plat->tx_queues_cfg[offset + i].weight !=
			    queue_weight) {
				NL_SET_ERR_MSG_FMT_MOD(extack, WEIGHT_ERR_MSG,
						       queue_weight, tc);
				return -EINVAL;
			}
		}
	}

update_mapping:
	val = readl(priv->ioaddr + GMAC5_MTL_FPE_CTRL_STS);
	writel(u32_replace_bits(val, preemptible_txqs, FPE_MTL_PREEMPTION_CLASS),
	       priv->ioaddr + GMAC5_MTL_FPE_CTRL_STS);

	return 0;
}

static void dwxgmac3_fpe_configure(void __iomem *ioaddr,
				   struct stmmac_fpe_cfg *cfg,
				   u32 num_txq, u32 num_rxq,
				   bool tx_enable, bool pmac_enable)
{
	common_fpe_configure(ioaddr, cfg, num_rxq, tx_enable,
			     pmac_enable, XGMAC_RXQ_CTRL1, XGMAC_FPRQ,
			     XGMAC_FPRQ_SHIFT, XGMAC_MAC_FPE_CTRL_STS,
			     XGMAC_INT_EN, XGMAC_FPEIE);
}

static int dwxgmac3_fpe_irq_status(void __iomem *ioaddr, struct net_device *dev)
{
	return common_fpe_irq_status(ioaddr + XGMAC_MAC_FPE_CTRL_STS, dev);
}

static void dwxgmac3_fpe_send_mpacket(void __iomem *ioaddr,
				      struct stmmac_fpe_cfg *cfg,
				      enum stmmac_mpacket_type type)
{
	common_fpe_send_mpacket(ioaddr + XGMAC_MAC_FPE_CTRL_STS, cfg, type);
}

static int dwxgmac3_fpe_get_add_frag_size(const void __iomem *ioaddr)
{
	return FIELD_GET(FPE_MTL_ADD_FRAG_SZ,
			 readl(ioaddr + XGMAC_MTL_FPE_CTRL_STS));
}

static void dwxgmac3_fpe_set_add_frag_size(void __iomem *ioaddr,
					   u32 add_frag_size)
{
	u32 value;

	value = readl(ioaddr + XGMAC_MTL_FPE_CTRL_STS);
	writel(u32_replace_bits(value, add_frag_size, FPE_MTL_ADD_FRAG_SZ),
	       ioaddr + XGMAC_MTL_FPE_CTRL_STS);
}

static int dwxgmac3_fpe_map_preemption_class(struct net_device *ndev,
					     struct netlink_ext_ack *extack,
					     u32 pclass)
{
	u32 val, offset, count, preemptible_txqs = 0;
	struct stmmac_priv *priv = netdev_priv(ndev);
	u32 num_tc = ndev->num_tc;

	if (!num_tc) {
		/* Restore default TC:Queue mapping */
		for (u32 i = 0; i < priv->plat->tx_queues_to_use; i++) {
			val = readl(priv->ioaddr + XGMAC_MTL_TXQ_OPMODE(i));
			writel(u32_replace_bits(val, i, XGMAC_Q2TCMAP),
			       priv->ioaddr + XGMAC_MTL_TXQ_OPMODE(i));
		}
	}

	/* Synopsys Databook:
	 * "All Queues within a traffic class are selected in a round robin
	 * fashion (when packets are available) when the traffic class is
	 * selected by the scheduler for packet transmission. This is true for
	 * any of the scheduling algorithms."
	 */
	for (u32 tc = 0; tc < num_tc; tc++) {
		count = ndev->tc_to_txq[tc].count;
		offset = ndev->tc_to_txq[tc].offset;

		if (pclass & BIT(tc))
			preemptible_txqs |= GENMASK(offset + count - 1, offset);

		for (u32 i = 0; i < count; i++) {
			val = readl(priv->ioaddr + XGMAC_MTL_TXQ_OPMODE(offset + i));
			writel(u32_replace_bits(val, tc, XGMAC_Q2TCMAP),
			       priv->ioaddr + XGMAC_MTL_TXQ_OPMODE(offset + i));
		}
	}

	val = readl(priv->ioaddr + XGMAC_MTL_FPE_CTRL_STS);
	writel(u32_replace_bits(val, preemptible_txqs, FPE_MTL_PREEMPTION_CLASS),
	       priv->ioaddr + XGMAC_MTL_FPE_CTRL_STS);

	return 0;
}

const struct stmmac_fpe_ops dwmac5_fpe_ops = {
	.fpe_configure = dwmac5_fpe_configure,
	.fpe_send_mpacket = dwmac5_fpe_send_mpacket,
	.fpe_irq_status = dwmac5_fpe_irq_status,
	.fpe_get_add_frag_size = dwmac5_fpe_get_add_frag_size,
	.fpe_set_add_frag_size = dwmac5_fpe_set_add_frag_size,
	.fpe_map_preemption_class = dwmac5_fpe_map_preemption_class,
};

const struct stmmac_fpe_ops dwxgmac_fpe_ops = {
	.fpe_configure = dwxgmac3_fpe_configure,
	.fpe_send_mpacket = dwxgmac3_fpe_send_mpacket,
	.fpe_irq_status = dwxgmac3_fpe_irq_status,
	.fpe_get_add_frag_size = dwxgmac3_fpe_get_add_frag_size,
	.fpe_set_add_frag_size = dwxgmac3_fpe_set_add_frag_size,
	.fpe_map_preemption_class = dwxgmac3_fpe_map_preemption_class,
};
