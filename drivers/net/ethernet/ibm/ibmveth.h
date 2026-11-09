/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * IBM Power Virtual Ethernet Device Driver
 *
 * Copyright (C) IBM Corporation, 2003, 2010
 *
 * Authors: Dave Larson <larson1@us.ibm.com>
 *	    Santiago Leon <santil@linux.vnet.ibm.com>
 *	    Brian King <brking@linux.vnet.ibm.com>
 *	    Robert Jennings <rcj@linux.vnet.ibm.com>
 *	    Anton Blanchard <anton@au.ibm.com>
 */

#ifndef _IBMVETH_H
#define _IBMVETH_H

#include <linux/completion.h>
#include <linux/spinlock_types.h>

/* constants for H_MULTICAST_CTRL */
#define IbmVethMcastReceptionModifyBit     0x80000UL
#define IbmVethMcastReceptionEnableBit     0x20000UL
#define IbmVethMcastFilterModifyBit        0x40000UL
#define IbmVethMcastFilterEnableBit        0x10000UL

#define IbmVethMcastEnableRecv       (IbmVethMcastReceptionModifyBit | IbmVethMcastReceptionEnableBit)
#define IbmVethMcastDisableRecv      (IbmVethMcastReceptionModifyBit)
#define IbmVethMcastEnableFiltering  (IbmVethMcastFilterModifyBit | IbmVethMcastFilterEnableBit)
#define IbmVethMcastDisableFiltering (IbmVethMcastFilterModifyBit)
#define IbmVethMcastAddFilter        0x1UL
#define IbmVethMcastRemoveFilter     0x2UL
#define IbmVethMcastClearFilterTable 0x3UL

#define IBMVETH_ILLAN_RX_MULTI_QUEUE_SUPPORT	0x0000000000080000UL
#define IBMVETH_ILLAN_RX_MULTI_BUFF_SUPPORT	0x0000000000040000UL
#define IBMVETH_ILLAN_LRG_SR_ENABLED	0x0000000000010000UL
#define IBMVETH_ILLAN_LRG_SND_SUPPORT	0x0000000000008000UL
#define IBMVETH_ILLAN_PADDED_PKT_CSUM	0x0000000000002000UL
#define IBMVETH_ILLAN_TRUNK_PRI_MASK	0x0000000000000F00UL
#define IBMVETH_ILLAN_IPV6_TCP_CSUM		0x0000000000000004UL
#define IBMVETH_ILLAN_IPV4_TCP_CSUM		0x0000000000000002UL
#define IBMVETH_ILLAN_ACTIVE_TRUNK		0x0000000000000001UL

#define IBMVETH_MIN_LSO_MSS		224	/* Minimum MSS for LSO */
/* hcall macros */
#define h_register_logical_lan(ua, buflst, rxq, fltlst, mac) \
  plpar_hcall_norets(H_REGISTER_LOGICAL_LAN, ua, buflst, rxq, fltlst, mac)

#define h_free_logical_lan(ua) \
  plpar_hcall_norets(H_FREE_LOGICAL_LAN, ua)

#define h_add_logical_lan_buffer(ua, buf) \
  plpar_hcall_norets(H_ADD_LOGICAL_LAN_BUFFER, ua, buf)

static inline long h_add_logical_lan_buffers(unsigned long unit_address,
					     unsigned long desc1,
					     unsigned long desc2,
					     unsigned long desc3,
					     unsigned long desc4,
					     unsigned long desc5,
					     unsigned long desc6,
					     unsigned long desc7,
					     unsigned long desc8)
{
	unsigned long retbuf[PLPAR_HCALL9_BUFSIZE];

	return plpar_hcall9(H_ADD_LOGICAL_LAN_BUFFERS,
			    retbuf, unit_address,
			    desc1, desc2, desc3, desc4,
			    desc5, desc6, desc7, desc8);
}

/**
 * h_register_logical_lan_queue - Register a subordinate receive queue
 * @unit_address: Device unit address
 * @buffer_list: DMA address of 4KB page for tracking registered buffers
 * @rec_queue: Buffer descriptor of receive queue
 * @queue_handle: Output queue handle on success (may be NULL)
 * @irq: Output hypervisor IRQ number on success (may be NULL)
 *
 * Registers a subordinate receive queue with the hypervisor.
 *
 * Return:
 *   H_SUCCESS (0) on success
 *   H_PARAMETER if parameters are invalid
 *   H_BUSY / H_LONG_BUSY_* if the resource is busy; retry
 *   H_FUNCTION if firmware does not support this hcall
 *
 * On success, hypervisor returns:
 *   R3: H_SUCCESS
 *   R4: Queue handle
 *   R5: IRQ number for this queue
 */
static inline long
h_register_logical_lan_queue(unsigned long unit_address,
			     unsigned long buffer_list,
			     unsigned long rec_queue,
			     unsigned long *queue_handle,
			     unsigned long *irq)
{
	unsigned long retbuf[PLPAR_HCALL_BUFSIZE];
	long rc;

	rc = plpar_hcall(H_REG_LOGICAL_LAN_QUEUE,
			 retbuf, unit_address,
			 buffer_list, rec_queue);

	if (rc == H_SUCCESS) {
		if (queue_handle)
			*queue_handle = retbuf[0];
		if (irq)
			*irq = retbuf[1];
	}

	return rc;
}

/**
 * h_add_logical_lan_buffers_queue - Add buffers to an RX queue by handle
 * @unit_address: Device unit address
 * @queue_handle: Queue handle from h_register_logical_lan_queue() or
 *		  h_register_logical_lan_with_handle() (queue 0)
 * @buffersznum: Buffer size (upper 32 bits) | count (lower 32 bits)
 * @ioba12: Buffer addresses 1 and 2 packed ((addr1 << 32) | addr2)
 * @ioba34: Buffer addresses 3 and 4 packed
 * @ioba56: Buffer addresses 5 and 6 packed
 * @ioba78: Buffer addresses 7 and 8 packed
 * @ioba910: Buffer addresses 9 and 10 packed
 * @ioba1112: Buffer addresses 11 and 12 packed
 *
 * Return:
 *   H_SUCCESS - All buffers added successfully
 *   H_PARAMETER - Invalid parameters
 *   H_HARDWARE - Hardware error
 *   H_FUNCTION - Firmware does not support this hcall
 */
static inline long h_add_logical_lan_buffers_queue(unsigned long unit_address,
						   unsigned long queue_handle,
						   unsigned long buffersznum,
						   unsigned long ioba12,
						   unsigned long ioba34,
						   unsigned long ioba56,
						   unsigned long ioba78,
						   unsigned long ioba910,
						   unsigned long ioba1112)
{
	unsigned long retbuf[PLPAR_HCALL9_BUFSIZE];

	return plpar_hcall9(H_ADD_LOGICAL_LAN_BUFFERS_QUEUE,
			    retbuf, unit_address,
			    queue_handle, buffersznum,
			    ioba12, ioba34, ioba56,
			    ioba78, ioba910, ioba1112);
}

/**
 * h_free_logical_lan_queue - Deregister a subordinate receive queue
 * @unit_address: Device unit address
 * @queue_handle: Queue handle from h_register_logical_lan_queue()
 *
 * Deregisters and frees all structures associated with the subordinate
 * queue. Queue 0 is torn down with the whole logical LAN by
 * H_FREE_LOGICAL_LAN.
 *
 * Return:
 *   H_SUCCESS - Queue freed successfully
 *   H_PARAMETER - The unit address has no logical LAN, or the handle
 *		   names no registered queue (already freed)
 *   H_HARDWARE - Hardware error
 *   H_STATE - VIOA not in valid state
 *   H_BUSY / H_LONG_BUSY_* - Resource busy, retry
 *   H_FUNCTION - Firmware does not support this hcall
 */
static inline long h_free_logical_lan_queue(unsigned long unit_address,
					    unsigned long queue_handle)
{
	return plpar_hcall_norets(H_FREE_LOGICAL_LAN_QUEUE,
				  unit_address, queue_handle);
}

/**
 * h_register_logical_lan_with_handle - Register primary queue and get handle
 * @unit_address: Device unit address
 * @buffer_list: DMA address of buffer list
 * @rec_queue: Buffer descriptor of receive queue
 * @filter_list: DMA address of filter list
 * @mac_address: MAC address
 * @queue_handle: Output parameter for queue handle (may be NULL)
 *
 * Registers the primary receive queue (queue 0) with the hypervisor and
 * returns the queue handle. This is needed in multi-queue mode to use
 * h_add_logical_lan_buffers_queue() for all queues including queue 0.
 * R4 carries a handle only on firmware that reports MQ RX support in
 * H_ILLAN_ATTRIBUTES; use h_register_logical_lan() otherwise.
 *
 * Return: H_SUCCESS (0) on success, error code otherwise
 */
static inline long
h_register_logical_lan_with_handle(unsigned long unit_address,
				   unsigned long buffer_list,
				   unsigned long rec_queue,
				   unsigned long filter_list,
				   unsigned long mac_address,
				   unsigned long *queue_handle)
{
	unsigned long retbuf[PLPAR_HCALL_BUFSIZE];
	long rc;

	rc = plpar_hcall(H_REGISTER_LOGICAL_LAN, retbuf,
			 unit_address, buffer_list, rec_queue,
			 filter_list, mac_address);

	if (rc == H_SUCCESS && queue_handle)
		*queue_handle = retbuf[0];

	return rc;
}

/* FW allows us to send 6 descriptors but we only use one so mark
 * the other 5 as unused (0)
 */
static inline long h_send_logical_lan(unsigned long unit_address,
		unsigned long desc, unsigned long corellator_in,
		unsigned long *corellator_out, unsigned long mss,
		unsigned long large_send_support)
{
	long rc;
	unsigned long retbuf[PLPAR_HCALL9_BUFSIZE];

	if (large_send_support)
		rc = plpar_hcall9(H_SEND_LOGICAL_LAN, retbuf, unit_address,
				  desc, 0, 0, 0, 0, 0, corellator_in, mss);
	else
		rc = plpar_hcall9(H_SEND_LOGICAL_LAN, retbuf, unit_address,
				  desc, 0, 0, 0, 0, 0, corellator_in);

	*corellator_out = retbuf[0];

	return rc;
}

static inline long h_illan_attributes(unsigned long unit_address,
				      unsigned long reset_mask, unsigned long set_mask,
				      unsigned long *ret_attributes)
{
	long rc;
	unsigned long retbuf[PLPAR_HCALL_BUFSIZE];

	rc = plpar_hcall(H_ILLAN_ATTRIBUTES, retbuf, unit_address,
			 reset_mask, set_mask);

	*ret_attributes = retbuf[0];

	return rc;
}

#define h_multicast_ctrl(ua, cmd, mac) \
  plpar_hcall_norets(H_MULTICAST_CTRL, ua, cmd, mac)

#define h_change_logical_lan_mac(ua, mac) \
  plpar_hcall_norets(H_CHANGE_LOGICAL_LAN_MAC, ua, mac)

#define IBMVETH_NUM_BUFF_POOLS 5
#define IBMVETH_IO_ENTITLEMENT_DEFAULT 4243456 /* MTU of 1500 needs 4.2Mb */
#define IBMVETH_BUFF_OH 22 /* Overhead: 14 ethernet header + 8 opaque handle */
#define IBMVETH_MIN_MTU 68
#define IBMVETH_MAX_POOL_COUNT 4096
#define IBMVETH_BUFF_LIST_SIZE 4096
#define IBMVETH_FILT_LIST_SIZE 4096
#define IBMVETH_MAX_BUF_SIZE (1024 * 128)
#define IBMVETH_MAX_TX_BUF_SIZE (1024 * 64)
#define IBMVETH_MAX_QUEUES 16U
#define IBMVETH_DEFAULT_QUEUES 8U
#define IBMVETH_MAX_RX_QUEUES 16U
#define IBMVETH_DEFAULT_RX_QUEUES 1U
#define IBMVETH_MAX_RX_REGULAR 8U
#define IBMVETH_MAX_RX_PER_HCALL 12U

static int pool_size[] = { 512, 1024 * 2, 1024 * 16, 1024 * 32, 1024 * 64 };
static int pool_count[] = { 256, 512, 256, 256, 256 };
static int pool_count_cmo[] = { 256, 512, 256, 256, 64 };
static int pool_active[] = { 1, 1, 0, 0, 1};

#define IBM_VETH_INVALID_MAP ((u16)0xffff)

/*
 * Per-queue RX counters. No field has two concurrent writers:
 * interrupts is written only from this queue's IRQ handler; polls,
 * packets, bytes, large_packets, invalid_buffers and dropped only from
 * its NAPI poll (polls not from netpoll's budget-0 call);
 * replenish_* only under its replenish_lock; and no_buffer_drops and
 * no_buffer_retired only under that lock. Readers snapshot that pair
 * under the same lock. No atomic or u64_stats_sync is therefore
 * needed: the driver is PPC64-only, so 64-bit loads and stores do not
 * tear. Readers still run locklessly on other CPUs, so writers use
 * IBMVETH_STAT_INC()/IBMVETH_STAT_ADD() and readers READ_ONCE(), which
 * keeps the compiler from splitting or refetching the accesses.
 */
struct ibmveth_rx_queue_stats {
	u64 packets;
	u64 bytes;
	u64 interrupts;
	u64 polls;
	u64 large_packets;
	u64 invalid_buffers;
	u64 dropped;
	/* PHYP's per-page absolute drop count for the live page. */
	u64 no_buffer_drops;
	/* Absolutes from pages this queue has already retired. */
	u64 no_buffer_retired;
	u64 replenish_task_cycles;
	u64 replenish_no_mem;
	u64 replenish_add_buff_failure;
	u64 replenish_add_buff_success;
} ____cacheline_aligned_in_smp;

/* Per-queue TX counters; serialized by the stack's per-queue TX lock. */
struct ibmveth_tx_queue_stats {
	u64 packets;
	u64 bytes;
	u64 large_packets;
	u64 dropped_packets;
	u64 send_failures;
} ____cacheline_aligned_in_smp;

struct ibmveth_buff_pool {
    u32 size;
    u32 index;
    u32 buff_size;
    u32 threshold;
    atomic_t available;
    u32 consumer_index;
    u32 producer_index;
    u16 *free_map;
    dma_addr_t *dma_addr;
    struct sk_buff **skbuff;
    int active;
    struct kobject kobj;
	struct completion released;
};

struct ibmveth_rx_q {
    u64        index;
    u64        num_slots;
    u64        toggle;
    dma_addr_t queue_dma;
    u32        queue_len;
    struct ibmveth_rx_q_entry *queue_addr;
	spinlock_t	replenish_lock;	/* per-queue buffer replenish */
};

struct ibmveth_adapter {
	struct vio_dev *vdev;
	struct net_device *netdev;
	struct napi_struct napi[IBMVETH_MAX_RX_QUEUES];
	struct work_struct work;
	unsigned int mcastFilterSize;
	void *buffer_list_addr[IBMVETH_MAX_RX_QUEUES];
	void *filter_list_addr;
	void *tx_ltb_ptr[IBMVETH_MAX_QUEUES];
	unsigned int tx_ltb_size;
	dma_addr_t tx_ltb_dma[IBMVETH_MAX_QUEUES];
	dma_addr_t buffer_list_dma[IBMVETH_MAX_RX_QUEUES];
	dma_addr_t filter_list_dma;
	struct ibmveth_buff_pool
		rx_buff_pool[IBMVETH_MAX_RX_QUEUES][IBMVETH_NUM_BUFF_POOLS];
	struct ibmveth_rx_q rx_queue[IBMVETH_MAX_RX_QUEUES];
	/* Opaque PHYP cookie; 0 can be live. queue_registered[] is slot-live,
	 * tracked only for multi_queue: SQ registration sets no handle.
	 */
	u64 queue_handle[IBMVETH_MAX_RX_QUEUES];
	bool queue_registered[IBMVETH_MAX_RX_QUEUES];
	unsigned int queue_irq[IBMVETH_MAX_RX_QUEUES];
	char queue_irq_name[IBMVETH_MAX_RX_QUEUES][32];
	bool multi_queue;
	unsigned int num_rx_queues;
	/* Set from replenish without RTNL: READ_ONCE()/WRITE_ONCE(). */
	bool mq_fallback;
	/* Lifetime: true while RX IRQ handlers / NAPI are installed. */
	bool rx_irq_setup;
	int rx_csum;
	int large_send;
	bool is_active_trunk;
	/* Set by a successful ibmveth_open(), cleared by ibmveth_close(). */
	bool opened;
	unsigned int rx_buffers_per_hcall;

	u64 fw_ipv6_csum_support;
	u64 fw_ipv4_csum_support;
	u64 fw_large_send_support;
	/*
	 * Every other ethtool -S counter lives in rx_qstats/tx_qstats and is
	 * summed on read. tx_map_failed predates multi-queue, has never been
	 * updated by any code path, and is kept only so the key keeps
	 * reporting the zero userspace already sees.
	 */
	u64 tx_map_failed;

	struct ibmveth_rx_queue_stats *rx_qstats;
	struct ibmveth_tx_queue_stats *tx_qstats;

	/* Ethtool settings */
	u8 duplex;
	u32 speed;
};

/*
 * We pass struct ibmveth_buf_desc_fields to the hypervisor in registers,
 * so we don't need to byteswap the two elements. However since we use
 * a union (ibmveth_buf_desc) to convert from the struct to a u64 we
 * do end up with endian specific ordering of the elements and that
 * needs correcting.
 */
struct ibmveth_buf_desc_fields {
#ifdef __BIG_ENDIAN
	u32 flags_len;
	u32 address;
#else
	u32 address;
	u32 flags_len;
#endif
#define IBMVETH_BUF_VALID	0x80000000
#define IBMVETH_BUF_TOGGLE	0x40000000
#define IBMVETH_BUF_LRG_SND     0x04000000
#define IBMVETH_BUF_NO_CSUM	0x02000000
#define IBMVETH_BUF_CSUM_GOOD	0x01000000
#define IBMVETH_BUF_LEN_MASK	0x00FFFFFF
};

union ibmveth_buf_desc {
    u64 desc;
    struct ibmveth_buf_desc_fields fields;
};

struct ibmveth_rx_q_entry {
	__be32 flags_off;
#define IBMVETH_RXQ_TOGGLE		0x80000000
#define IBMVETH_RXQ_TOGGLE_SHIFT	31
#define IBMVETH_RXQ_VALID		0x40000000
#define IBMVETH_RXQ_LRG_PKT		0x04000000
#define IBMVETH_RXQ_NO_CSUM		0x02000000
#define IBMVETH_RXQ_CSUM_GOOD		0x01000000
#define IBMVETH_RXQ_OFF_MASK		0x0000FFFF

	__be32 length;
	/* correlator is only used by the OS, no need to byte swap */
	u64 correlator;
};

#endif /* _IBMVETH_H */
