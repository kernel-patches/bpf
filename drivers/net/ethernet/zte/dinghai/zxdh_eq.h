/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * ZTE DingHai Ethernet driver - event queue abstraction
 * Copyright (c) 2022-2026, ZTE Corporation.
 */

#ifndef __ZXDH_EQ_H__
#define __ZXDH_EQ_H__

#include <linux/mutex.h>
#include <linux/notifier.h>

struct zxdh_core_dev;
struct zxdh_irq;

/* BAR message area: shared-memory mailbox between the driver and the
 * firmware, split into sub-channels of 2048 bytes. Notifications from
 * the RISC-V management core are posted to the PF receive sub-channel,
 * one interval above the area base.
 */
#define ZXDH_BAR_MSG_OFFSET		0x2000
#define ZXDH_BAR_MSG_SUBCHAN_INTERVAL	2048
#define ZXDH_BAR_MSG_SUBCHAN_RECV	(ZXDH_BAR_MSG_OFFSET +	\
					 ZXDH_BAR_MSG_SUBCHAN_INTERVAL)

/* event_id of the "RISC-V core ready" firmware notification, carried
 * at byte offset 2 of the BAR message header.
 */
#define ZXDH_MSG_MODULE_RISC_READY	13

/* Event types the upper layers can subscribe to over the per-type
 * notifier chains of the event queue table. The full catalogue lives
 * in the firmware; only the ones dispatched in this series are named.
 */
enum zxdh_eq_event_type {
	ZXDH_EQ_EVENT_TYPE_RISCV_READY = 0,
	ZXDH_EQ_EVENT_TYPE_MAX,
};

/* Asynchronous event queue delivering firmware notifications to the
 * driver without a request/reply handshake.
 */
struct zxdh_eq_async {
	struct zxdh_irq *irq;
	struct notifier_block irq_nb;
	void *priv;
};

struct zxdh_eq_table {
	/* Notifier chains fanned out by event type. */
	struct atomic_notifier_head nh[ZXDH_EQ_EVENT_TYPE_MAX];
	/* Serializes async EQ create/destroy. */
	struct mutex lock;
	void *priv;
};

int zxdh_pf_eq_table_init(struct zxdh_core_dev *zxdh_dev);
int zxdh_pf_eq_table_create(struct zxdh_core_dev *zxdh_dev);
void zxdh_pf_eq_table_destroy(struct zxdh_core_dev *zxdh_dev);

#endif /* __ZXDH_EQ_H__ */
