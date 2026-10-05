// SPDX-License-Identifier: GPL-2.0
/* Texas Instruments ICSSM Ethernet Driver
 *
 * Copyright (C) 2018-2022 Texas Instruments Incorporated - https://www.ti.com/
 *
 */

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/if_vlan.h>

#include "icssm_prueth.h"
#include "icssm_prueth_switch.h"

static int icssm_prueth_common_emac_rx_packets(struct prueth_emac *emac,
					       int quota, u8 qid1, u8 qid2)
{
	u16 bd_rd_ptr, bd_wr_ptr, update_rd_ptr, bd_rd_ptr_o, bd_wr_ptr_o;
	const struct prueth_queue_info *rxqueue, *rxqueue_o, *rxqueue_p;
	struct prueth_packet_info pkt_info, pkt_info_o, *pkt_info_p;
	u32 rd_buf_desc, rd_buf_desc_o, pkt_ts, pkt_ts_o, iep_wrap;
	int ret, used = 0, port, port0_q_empty, port1_q_empty;
	struct prueth_queue_desc __iomem *queue_desc_o = NULL;
	struct prueth_queue_desc __iomem *queue_desc = NULL;
	struct prueth_emac *emac_p, *other_emac;
	void __iomem *shared_ram, *ocmc_ram;
	bool port0_configured, port1_configured;
	u8 overflow_cnt, overflow_cnt_o;
	u16 *bd_rd_ptr_p, *bd_wr_ptr_p;
	struct prueth *prueth;

	prueth = emac->prueth;
	ocmc_ram = prueth->mem[PRUETH_MEM_OCMC].va;
	shared_ram = prueth->mem[PRUETH_MEM_SHARED_RAM].va;
	other_emac = prueth->emac[(emac->port_id == PRUETH_PORT_MII0) ?
			PRUETH_PORT_MII1 - 1 : PRUETH_PORT_MII0 - 1];

	iep_wrap = prueth->fw_offsets.iep_wrap;
	rxqueue = &sw_queue_infos[PRUETH_PORT_HOST][qid1];
	rxqueue_o = &sw_queue_infos[PRUETH_PORT_HOST][qid2];

	/* skip Rx if budget is 0 */
	if (!quota)
		return 0;

	/* A port's rx_queue_descs is only valid once that port has
	 * completed its own ndo_open() for the currently active mode:
	 * before that it is NULL (never opened) or stale (opened in a
	 * different mode), since the shared HP/LP IRQs and PRUs are
	 * started as soon as the first port opens, independent of the
	 * peer port's state. Treat an unconfigured port's queue as
	 * permanently empty instead of dereferencing rx_queue_descs.
	 */
	port0_configured = prueth->emac_configured & BIT(emac->port_id);
	port1_configured = other_emac &&
			   (prueth->emac_configured & BIT(other_emac->port_id));

	if (port0_configured) {
		queue_desc = emac->rx_queue_descs + qid1;

		overflow_cnt = readb(&queue_desc->overflow_cnt);
		if (overflow_cnt > 0) {
			atomic64_add(overflow_cnt, &emac->stats.rx_over_errors);
			writeb(0, &queue_desc->overflow_cnt);
		}

		bd_rd_ptr = readw(&queue_desc->rd_ptr);
		bd_wr_ptr = readw(&queue_desc->wr_ptr);
		port0_q_empty = (bd_rd_ptr == bd_wr_ptr);
	} else {
		bd_rd_ptr = 0;
		bd_wr_ptr = 0;
		port0_q_empty = 1;
	}

	if (port1_configured) {
		queue_desc_o = other_emac->rx_queue_descs + qid2;

		overflow_cnt_o = readb(&queue_desc_o->overflow_cnt);
		if (overflow_cnt_o > 0) {
			atomic64_add(overflow_cnt_o,
				     &other_emac->stats.rx_over_errors);
			writeb(0, &queue_desc_o->overflow_cnt);
		}

		bd_rd_ptr_o = readw(&queue_desc_o->rd_ptr);
		bd_wr_ptr_o = readw(&queue_desc_o->wr_ptr);
		port1_q_empty = (bd_rd_ptr_o == bd_wr_ptr_o);
	} else {
		bd_rd_ptr_o = 0;
		bd_wr_ptr_o = 0;
		port1_q_empty = 1;
	}

	while (!port0_q_empty || !port1_q_empty) {
		rd_buf_desc = readl(shared_ram + bd_rd_ptr);
		rd_buf_desc_o = readl(shared_ram + bd_rd_ptr_o);

		icssm_parse_packet_info(prueth, rd_buf_desc, &pkt_info);
		icssm_parse_packet_info(prueth, rd_buf_desc_o, &pkt_info_o);

		pkt_ts = readl(ocmc_ram + ICSS_LRE_TIMESTAMP_ARRAY_OFFSET +
			       bd_rd_ptr - SRAM_START_OFFSET);
		pkt_ts_o = readl(ocmc_ram + ICSS_LRE_TIMESTAMP_ARRAY_OFFSET +
				 bd_rd_ptr_o - SRAM_START_OFFSET);

		if (!port0_q_empty && !port1_q_empty) {
			/* Both ports have a pending frame, pick the
			 * earlier one by comparing timestamps and
			 * account for wraparound.
			 */
			if (pkt_ts > pkt_ts_o)
				port = (pkt_ts - pkt_ts_o) > (iep_wrap / 2) ?
					0 : 1;
			else
				port = (pkt_ts_o - pkt_ts) > (iep_wrap / 2) ?
					1 : 0;

		} else if (!port0_q_empty) {
			/* Packet(s) in port0 queue only */
			port = 0;
		} else {
			/* Packet(s) in port1 queue only */
			port = 1;
		}

		/* Select correct data structures for queue/packet selected */
		if (port == 0) {
			pkt_info_p = &pkt_info;
			bd_wr_ptr_p = &bd_wr_ptr;
			bd_rd_ptr_p = &bd_rd_ptr;
			emac_p = emac;
			rxqueue_p = rxqueue;
		} else {
			pkt_info_p = &pkt_info_o;
			bd_wr_ptr_p = &bd_wr_ptr_o;
			bd_rd_ptr_p = &bd_rd_ptr_o;
			emac_p = other_emac;
			rxqueue_p = rxqueue_o;
		}

		if ((*pkt_info_p).length < EMAC_MIN_PKTLEN) {
			/* Undersized frame: firmware should have filtered
			 * it, so the read pointer can't be trusted. Drop
			 * everything pending in this queue by moving the
			 * read pointer to the write pointer.
			 */
			update_rd_ptr = *bd_wr_ptr_p;
			atomic64_inc(&emac_p->stats.rx_length_errors);
		} else if ((*pkt_info_p).length > EMAC_MAX_FRM_SUPPORT) {
			/* Oversized frame: same handling as above */
			update_rd_ptr = *bd_wr_ptr_p;
			atomic64_inc(&emac_p->stats.rx_length_errors);
		} else {
			update_rd_ptr = *bd_rd_ptr_p;
			ret = icssm_emac_rx_packet(emac_p, &update_rd_ptr,
						   pkt_info_p, rxqueue_p);
			if (ret)
				return used;

			used++;
		}

		/* Leave the BD intact after reading. Firmware reuses it to
		 * forward the frame to the second LRE port.
		 */
		if (port == 0) {
			if (PRUETH_IS_SWITCH(prueth))
				writel(0, shared_ram + bd_rd_ptr);
			writew(update_rd_ptr, &queue_desc->rd_ptr);
			bd_rd_ptr = update_rd_ptr;
		} else {
			if (PRUETH_IS_SWITCH(prueth))
				writel(0, shared_ram + bd_rd_ptr_o);
			writew(update_rd_ptr, &queue_desc_o->rd_ptr);
			bd_rd_ptr_o = update_rd_ptr;
		}

		port0_q_empty = (bd_rd_ptr == bd_wr_ptr) ? 1 : 0;
		port1_q_empty = (bd_rd_ptr_o == bd_wr_ptr_o) ? 1 : 0;

		if (used >= quota)
			return used;
	}

	return used;
}

int icssm_prueth_common_napi_poll_lpq(struct napi_struct *napi, int budget)
{
	struct prueth_emac *emac;
	struct net_device *ndev;
	struct prueth *prueth;
	int num_rx_packets;
	u8 qid1, qid2;

	prueth = container_of(napi, struct prueth, napi_lpq);
	ndev = prueth->lp->ndev;
	emac = netdev_priv(ndev);
	qid1 = PRUETH_QUEUE2;
	qid2 = PRUETH_QUEUE4;

	num_rx_packets = icssm_prueth_common_emac_rx_packets(emac, budget,
							     qid1, qid2);
	if (num_rx_packets < budget && napi_complete_done(napi, num_rx_packets))
		enable_irq(prueth->rx_lpq_irq);

	return num_rx_packets;
}

int icssm_prueth_common_napi_poll_hpq(struct napi_struct *napi, int budget)
{
	struct prueth_emac *emac;
	struct net_device *ndev;
	struct prueth *prueth;
	int num_rx_packets;
	u8 qid1, qid2;

	prueth = container_of(napi, struct prueth, napi_hpq);
	ndev = prueth->hp->ndev;
	emac = netdev_priv(ndev);
	qid1 = PRUETH_QUEUE1;
	qid2 = PRUETH_QUEUE3;

	num_rx_packets = icssm_prueth_common_emac_rx_packets(emac, budget,
							     qid1, qid2);
	if (num_rx_packets < budget && napi_complete_done(napi, num_rx_packets))
		enable_irq(prueth->rx_hpq_irq);

	return num_rx_packets;
}

static irqreturn_t icssm_prueth_common_emac_rx_hardirq(int irq, void *dev_id)
{
	struct prueth_ndev_priority *ndev_prio;
	struct prueth_emac *emac;
	struct net_device *ndev;
	struct prueth *prueth;

	ndev_prio = (struct prueth_ndev_priority *)dev_id;
	ndev = ndev_prio->ndev;
	emac = netdev_priv(ndev);
	prueth = emac->prueth;

	/* disable Rx system event */
	if (ndev_prio->priority == 1) {
		disable_irq_nosync(prueth->rx_lpq_irq);
		napi_schedule(&prueth->napi_lpq);
	} else {
		disable_irq_nosync(prueth->rx_hpq_irq);
		napi_schedule(&prueth->napi_hpq);
	}

	return IRQ_HANDLED;
}

int icssm_prueth_common_request_irqs(struct prueth_emac *emac)
{
	struct prueth *prueth = emac->prueth;
	int ret;

	/* Request irq when first port is initialized */
	if (prueth->emac_configured)
		return 0;

	ret = request_irq(prueth->rx_hpq_irq,
			  icssm_prueth_common_emac_rx_hardirq,
			  IRQF_TRIGGER_HIGH, "eth_hp_int", prueth->hp);
	if (ret) {
		netdev_err(emac->ndev, "unable to request RX HPQ IRQ\n");
		goto free_napi_hpq_lpq;
	}

	ret = request_irq(prueth->rx_lpq_irq,
			  icssm_prueth_common_emac_rx_hardirq,
			  IRQF_TRIGGER_HIGH, "eth_lp_int", prueth->lp);
	if (ret) {
		netdev_err(emac->ndev, "unable to request RX LPQ IRQ\n");
		goto free_rx_hpq_irq;
	}

	return 0;

free_rx_hpq_irq:
	free_irq(prueth->rx_hpq_irq, prueth->hp);

free_napi_hpq_lpq:
	napi_disable(&prueth->napi_lpq);
	napi_disable(&prueth->napi_hpq);

	return ret;
}

/**
 * icssm_prueth_common_free_irqs - free irq
 *
 * @emac: EMAC data structure
 *
 */
void icssm_prueth_common_free_irqs(struct prueth_emac *emac)
{
	struct prueth *prueth = emac->prueth;

	/* HSR/PRP/Switch: free irqs when last port is down */
	if (prueth->emac_configured)
		return;

	free_irq(prueth->rx_lpq_irq, prueth->lp);
	free_irq(prueth->rx_hpq_irq, prueth->hp);
}
