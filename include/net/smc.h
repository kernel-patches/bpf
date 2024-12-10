/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  Shared Memory Communications over RDMA (SMC-R) and RoCE
 *
 *  Definitions for the SMC module (socket related)
 *
 *  Copyright IBM Corp. 2016
 *
 *  Author(s):  Ursula Braun <ubraun@linux.vnet.ibm.com>
 */
#ifndef _SMC_H
#define _SMC_H

#include <linux/device.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/wait.h>
#include "linux/ism.h"

struct sock;
struct tcp_sock;
struct inet_request_sock;

#define SMC_MAX_PNETID_LEN	16	/* Max. length of PNET id */

struct smc_hashinfo {
	rwlock_t lock;
	struct hlist_head ht;
};

/* SMCD/ISM device driver interface */
struct smcd_dmb {
	u64 dmb_tok;
	u64 rgid;
	u32 dmb_len;
	u32 sba_idx;
	u32 vlan_valid;
	u32 vlan_id;
	void *cpu_addr;
	dma_addr_t dma_addr;
};

#define ISM_EVENT_DMB	0
#define ISM_EVENT_GID	1
#define ISM_EVENT_SWR	2

#define ISM_RESERVED_VLANID	0x1FFF

#define ISM_ERROR	0xFFFF

struct smcd_dev;

struct smcd_gid {
	u64	gid;
	u64	gid_ext;
};

struct smcd_ops {
	int (*query_remote_gid)(struct smcd_dev *dev, struct smcd_gid *rgid,
				u32 vid_valid, u32 vid);
	int (*register_dmb)(struct smcd_dev *dev, struct smcd_dmb *dmb,
			    void *client);
	int (*unregister_dmb)(struct smcd_dev *dev, struct smcd_dmb *dmb);
	int (*move_data)(struct smcd_dev *dev, u64 dmb_tok, unsigned int idx,
			 bool sf, unsigned int offset, void *data,
			 unsigned int size);
	int (*supports_v2)(void);
	void (*get_local_gid)(struct smcd_dev *dev, struct smcd_gid *gid);
	u16 (*get_chid)(struct smcd_dev *dev);
	struct device* (*get_dev)(struct smcd_dev *dev);

	/* optional operations */
	int (*add_vlan_id)(struct smcd_dev *dev, u64 vlan_id);
	int (*del_vlan_id)(struct smcd_dev *dev, u64 vlan_id);
	int (*set_vlan_required)(struct smcd_dev *dev);
	int (*reset_vlan_required)(struct smcd_dev *dev);
	int (*signal_event)(struct smcd_dev *dev, struct smcd_gid *rgid,
			    u32 trigger_irq, u32 event_code, u64 info);
	int (*support_dmb_nocopy)(struct smcd_dev *dev);
	int (*attach_dmb)(struct smcd_dev *dev, struct smcd_dmb *dmb);
	int (*detach_dmb)(struct smcd_dev *dev, u64 token);
};

struct smcd_dev {
	const struct smcd_ops *ops;
	void *priv;
	void *client;
	struct list_head list;
	spinlock_t lock;
	struct smc_connection **conn;
	struct list_head vlan;
	struct workqueue_struct *event_wq;
	u8 pnetid[SMC_MAX_PNETID_LEN];
	bool pnetid_by_user;
	struct list_head lgr_list;
	spinlock_t lgr_lock;
	atomic_t lgr_cnt;
	wait_queue_head_t lgrs_deleted;
	u8 going_away : 1;
};

#define  SMC_OPS_NAME_MAX 16

enum {
	/* ops can be inherit from init_net */
	SMC_OPS_FLAG_INHERITABLE = 0x1,

	SMC_OPS_ALL_FLAGS = SMC_OPS_FLAG_INHERITABLE,
};

struct smc_ops {
	/* priavte */

	struct list_head list;
	struct module *owner;

	/* public */

	/* unique name */
	char name[SMC_OPS_NAME_MAX];
	int flags;

	/* Invoked before computing SMC option for SYN packets.
	 * We can control whether to set SMC options by returning varios value.
	 * Return 0 to disable SMC, or return any other value to enable it.
	 */
	int (*set_option)(struct tcp_sock *tp);

	/* Invoked before Set up SMC options for SYN-ACK packets
	 * We can control whether to respond SMC options by returning varios value.
	 * Return 0 to disable SMC, or return any other value to enable it.
	 */
	int (*set_option_cond)(const struct tcp_sock *tp, struct inet_request_sock *ireq);
};

#if IS_ENABLED(CONFIG_SMC_OPS)
#define smc_call_retops(init_val, sk, func, ...) ({	\
	typeof(init_val) __ret = (init_val);		\
	struct smc_ops *ops;				\
	rcu_read_lock();				\
	ops = READ_ONCE(sock_net(sk)->smc.ops);		\
	if (ops && ops->func)				\
		__ret = ops->func(__VA_ARGS__);		\
	rcu_read_unlock();				\
	__ret;						\
})
#else
#define smc_call_retops(init_val, ...) (init_val)
#endif /* CONFIG_SMC_OPS */

#endif	/* _SMC_H */
