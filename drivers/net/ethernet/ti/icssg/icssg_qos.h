/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2023 Texas Instruments Incorporated - http://www.ti.com/
 */

#ifndef __NET_TI_ICSSG_QOS_H
#define __NET_TI_ICSSG_QOS_H

#include <linux/atomic.h>
#include <linux/netdevice.h>
#include <net/pkt_sched.h>

#define ICSSG_MAX_TC_QUEUES			8
#define ICSSG_EXPRESS_Q_MASK_ALL		0xFF
#define ICSSG_IET_MAX_VERIFY_TIME		128
#define ICSSG_IET_MIN_VERIFY_TIME		1
#define ICSSG_IET_VERIFY_ATTEMPTS		3

/**
 * enum icssg_ietfpe_verify_states - status of MM Verify returned by firmware
 * @ICSSG_IETFPE_STATE_UNKNOWN:
 *	verification status is unknown
 * @ICSSG_IETFPE_STATE_INITIAL:
 *	Firmware returns this if verify state diagram is idle
 * @ICSSG_IETFPE_STATE_VERIFYING:
 *	Firmware returns this if verification is ongoing
 * @ICSSG_IETFPE_STATE_SUCCEEDED:
 *	Firmware returns this if verify state diagram completes verification
 * @ICSSG_IETFPE_STATE_FAILED:
 *	Firmware returns this if verify state diagram fails during verification
 * @ICSSG_IETFPE_STATE_DISABLED:
 *	verification is disabled by the driver
 */
enum icssg_ietfpe_verify_states {
	ICSSG_IETFPE_STATE_UNKNOWN = 0,
	ICSSG_IETFPE_STATE_INITIAL,
	ICSSG_IETFPE_STATE_VERIFYING,
	ICSSG_IETFPE_STATE_SUCCEEDED,
	ICSSG_IETFPE_STATE_FAILED,
	ICSSG_IETFPE_STATE_DISABLED
};

struct prueth_qos_mqprio {
	struct tc_mqprio_qopt qopt;
};

struct prueth_qos_iet {
	bool fpe_enabled;
	bool mac_verify_configure;
	u32 tx_min_frag_size;
	u32 verify_time_ms;
	bool fpe_active;
	enum icssg_ietfpe_verify_states verify_status;
	/* fpe mutex protects all FPE operations for synchronization */
	struct mutex fpe_lock;
	u8 preemptible_tcs;
};

struct prueth_qos {
	struct prueth_qos_iet iet;
	struct prueth_qos_mqprio mqprio;
};

void icssg_qos_init(struct net_device *ndev);
void icssg_qos_link_state_update(struct net_device *ndev);
int icssg_qos_ndo_setup_tc(struct net_device *ndev, enum tc_setup_type type,
			   void *type_data);
int icssg_config_ietfpe(struct net_device *ndev, bool enable);
#endif /* __NET_TI_ICSSG_QOS_H */
