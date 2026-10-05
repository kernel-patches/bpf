// SPDX-License-Identifier: GPL-2.0

/* Texas Instruments PRUETH hsr/prp Link Redundancy Entity (LRE) Driver.
 *
 * Copyright (C) 2020 Texas Instruments Incorporated - http://www.ti.com
 */

#include <linux/kernel.h>
#include <linux/string.h>

#include "icssm_lre_firmware.h"
#include "icssm_prueth_lre.h"
#include "icssm_prueth.h"
#include "icssm_prueth_switch.h"

void icssm_prueth_lre_config_check_flags(struct prueth *prueth)
{
	void __iomem *dram1 = prueth->mem[PRUETH_MEM_DRAM1].va;

	/* HSR/PRP: initialize check table when first port is up */
	if (prueth->emac_configured)
		return;

	prueth->tbl_check_mask = ICSS_LRE_HOST_TIMER_HOST_TABLE_CHECK_BIT;
	if (PRUETH_IS_HSR(prueth))
		prueth->tbl_check_mask |=
			ICSS_LRE_HOST_TIMER_PORT_TABLE_CHECK_BITS;
	writel(prueth->tbl_check_mask, dram1 + ICSS_LRE_HOST_TIMER_CHECK_FLAGS);
}

/* A group of PCPs are mapped to a Queue. This is the size of firmware
 * array in shared memory
 */
#define PCP_GROUP_TO_QUEUE_MAP_SIZE	4

/* PRU firmware default PCP to priority Queue map for ingress & egress
 *
 * At ingress to Host
 * ==================
 * byte 0 => PRU 1, PCP 0-3 => Q3
 * byte 1 => PRU 1, PCP 4-7 => Q2
 * byte 2 => PRU 0, PCP 0-3 => Q1
 * byte 3 => PRU 0, PCP 4-7 => Q0
 *
 * At egress to wire/network on PRU-0 and PRU-1
 * ============================================
 * byte 0 => Host, PCP 0-3 => Q3
 * byte 1 => Host, PCP 4-7 => Q2
 *
 * PRU-0
 * -----
 * byte 2 => PRU-1, PCP 0-3 => Q1
 * byte 3 => PRU-1, PCP 4-7 => Q0
 *
 * PRU-1
 * -----
 * byte 2 => PRU-0, PCP 0-3 => Q1
 * byte 3 => PRU-0, PCP 4-7 => Q0
 *
 * queue names below are named 1 based. i.e PRUETH_QUEUE1 is Q0,
 * PRUETH_QUEUE2 is Q1 and so forth. Firmware convention is that
 * a lower queue number has higher priority than a higher queue
 * number.
 */
static u8 fw_pcp_default_priority_queue_map[PCP_GROUP_TO_QUEUE_MAP_SIZE] = {
	/* port 2 or PRU 1 */
	PRUETH_QUEUE4, PRUETH_QUEUE3,
	/* port 1 or PRU 0 */
	PRUETH_QUEUE2, PRUETH_QUEUE1,
};

static void icssm_prueth_lre_pcp_queue_map_config(struct prueth *prueth)
{
	void __iomem *sram = prueth->mem[PRUETH_MEM_SHARED_RAM].va;

	memcpy_toio(sram + ICSS_LRE_QUEUE_2_PCP_MAP_OFFSET,
		    &fw_pcp_default_priority_queue_map[0],
		    PCP_GROUP_TO_QUEUE_MAP_SIZE);
}

static void icssm_prueth_lre_host_table_init(struct prueth *prueth)
{
	void __iomem *dram0 = prueth->mem[PRUETH_MEM_DRAM0].va;
	void __iomem *dram1 = prueth->mem[PRUETH_MEM_DRAM1].va;

	memset_io(dram0 + ICSS_LRE_DUPLICATE_HOST_TABLE, 0,
		  ICSS_LRE_DUPLICATE_HOST_TABLE_DMEM_SIZE);

	writel(ICSS_LRE_DUPLICATE_HOST_TABLE_SIZE_INIT,
	       dram1 + ICSS_LRE_DUPLICATE_HOST_TABLE_SIZE);

	writel(ICSS_LRE_TABLE_CHECK_RESOLUTION_10_MS,
	       dram1 + ICSS_LRE_DUPLI_HOST_CHECK_RESO);

	writel(ICSS_LRE_MASTER_SLAVE_BUSY_BITS_CLEAR,
	       dram1 + ICSS_LRE_HOST_DUPLICATE_ARBITRATION);
}

static void icssm_prueth_lre_port_table_init(struct prueth *prueth)
{
	void __iomem *dram1 = prueth->mem[PRUETH_MEM_DRAM1].va;

	if (PRUETH_IS_HSR(prueth)) {
		memset_io(dram1 + ICSS_LRE_DUPLICATE_PORT_TABLE_PRU0, 0,
			  ICSS_LRE_DUPLICATE_PORT_TABLE_DMEM_SIZE);
		memset_io(dram1 + ICSS_LRE_DUPLICATE_PORT_TABLE_PRU1, 0,
			  ICSS_LRE_DUPLICATE_PORT_TABLE_DMEM_SIZE);

		writel(ICSS_LRE_DUPLICATE_PORT_TABLE_SIZE_INIT,
		       dram1 + ICSS_LRE_DUPLICATE_PORT_TABLE_SIZE);
	} else {
		writel(0, dram1 + ICSS_LRE_DUPLICATE_PORT_TABLE_SIZE);
	}

	writel(ICSS_LRE_TABLE_CHECK_RESOLUTION_10_MS,
	       dram1 + ICSS_LRE_DUPLI_PORT_CHECK_RESO);
}

static void icssm_prueth_lre_init(struct prueth *prueth)
{
	void __iomem *sram = prueth->mem[PRUETH_MEM_SHARED_RAM].va;

	memset_io(sram + ICSS_LRE_START, 0, ICSS_LRE_STATS_DMEM_SIZE);

	writel(ICSS_LRE_IEC62439_CONST_DUPLICATE_DISCARD,
	       sram + ICSS_LRE_DUPLICATE_DISCARD);
	writel(ICSS_LRE_IEC62439_CONST_TRANSP_RECEPTION_REMOVE_RCT,
	       sram + ICSS_LRE_TRANSPARENT_RECEPTION);
}

static void icssm_prueth_lre_dbg_init(struct prueth *prueth)
{
	void __iomem *dram0 = prueth->mem[PRUETH_MEM_DRAM0].va;

	memset_io(dram0 + ICSS_LRE_DBG_START, 0,
		  ICSS_LRE_DEBUG_COUNTER_DMEM_SIZE);
}

static void icssm_prueth_lre_protocol_init(struct prueth *prueth)
{
	void __iomem *dram0 = prueth->mem[PRUETH_MEM_DRAM0].va;
	void __iomem *dram1 = prueth->mem[PRUETH_MEM_DRAM1].va;

	if (PRUETH_IS_HSR(prueth))
		writew(ICSS_LRE_MODEH, dram0 + ICSS_LRE_HSR_MODE_OFFSET);

	writel(ICSS_LRE_DUPLICATE_FORGET_TIME_400_MS,
	       dram1 + ICSS_LRE_DUPLI_FORGET_TIME);
	writel(ICSS_LRE_SUP_ADDRESS_INIT_OCTETS_HIGH,
	       dram1 + ICSS_LRE_SUP_ADDR);
	writel(ICSS_LRE_SUP_ADDRESS_INIT_OCTETS_LOW,
	       dram1 + ICSS_LRE_SUP_ADDR_LOW);
}

static void icssm_prueth_lre_config_packet_timestamping(struct prueth *prueth)
{
	void __iomem *sram = prueth->mem[PRUETH_MEM_SHARED_RAM].va;

	writeb(1, sram + ICSS_LRE_PRIORITY_INTRS_STATUS_OFFSET);
	writeb(1, sram + ICSS_LRE_TIMESTAMP_PKTS_STATUS_OFFSET);
}

static enum hrtimer_restart icssm_prueth_lre_timer(struct hrtimer *timer)
{
	struct prueth *prueth;
	unsigned int timeout;
	void __iomem *dram;

	prueth = container_of(timer, struct prueth, tbl_check_timer);
	dram = prueth->mem[PRUETH_MEM_DRAM1].va;
	timeout = PRUETH_TIMER_MS;

	hrtimer_forward_now(timer, ms_to_ktime(timeout));
	if (prueth->emac_configured !=
	    (BIT(PRUETH_PORT_MII0) | BIT(PRUETH_PORT_MII1)))
		return HRTIMER_RESTART;

	/* Set the flags for duplicate tables so the firmware checks and
	 * updates them every 10 milliseconds.
	 */
	writel(prueth->tbl_check_mask, dram + ICSS_LRE_HOST_TIMER_CHECK_FLAGS);

	return HRTIMER_RESTART;
}

static void icssm_prueth_lre_init_timer(struct prueth *prueth)
{
	hrtimer_setup(&prueth->tbl_check_timer, &icssm_prueth_lre_timer,
		      CLOCK_MONOTONIC, HRTIMER_MODE_REL);
}

static void icssm_prueth_lre_start_timer(struct prueth *prueth)
{
	unsigned int timeout = PRUETH_TIMER_MS;

	if (hrtimer_active(&prueth->tbl_check_timer))
		return;

	hrtimer_start(&prueth->tbl_check_timer, ms_to_ktime(timeout),
		      HRTIMER_MODE_REL);
}

void icssm_prueth_lre_config(struct prueth *prueth)
{
	icssm_prueth_lre_init_timer(prueth);
	icssm_prueth_lre_start_timer(prueth);
	icssm_prueth_lre_pcp_queue_map_config(prueth);
	icssm_prueth_lre_host_table_init(prueth);
	icssm_prueth_lre_port_table_init(prueth);
	icssm_prueth_lre_init(prueth);
	icssm_prueth_lre_dbg_init(prueth);
	icssm_prueth_lre_protocol_init(prueth);
	/* Enable per-packet timestamping so the driver can order
	 * received frames by arrival time across the two slave ports.
	 */
	icssm_prueth_lre_config_packet_timestamping(prueth);

}

void icssm_prueth_lre_cleanup(struct prueth *prueth)
{
	if (hrtimer_active(&prueth->tbl_check_timer))
		hrtimer_cancel(&prueth->tbl_check_timer);
}
