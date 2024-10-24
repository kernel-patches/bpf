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

/*
 * This structure is used to store the parameters passed to the member of struct_ops.
 * Due to the BPF verifier cannot restrict the writing of bit fields, such as limiting
 * it to only write ireq->smc_ok. Using kfunc can solve this issue, but we don't want
 * to introduce a kfunc with such a narrow function.
 *
 * Moreover, using this structure for unified parameters also addresses another
 * potential issue. Currently, kfunc cannot recognize the calling context
 * through BPF's existing structure. In the future, we can solve this problem
 * by passing this ctx to kfunc.
 */
struct smc_bpf_ops_ctx {
	struct {
		struct tcp_sock *tp;
	} set_option;
	struct {
		const struct tcp_sock *tp;
		struct inet_request_sock *ireq;
		int smc_ok;
	} set_option_cond;
};

struct smc_bpf_ops {
	/* priavte */

	struct list_head	list;

	/* public */

	/* Invoked before computing SMC option for SYN packets.
	 * We can control whether to set SMC options by modifying
	 * ctx->set_option->tp->syn_smc.
	 * This's also the only member that can be modified now.
	 * Only member in ctx->set_option is valid for this callback.
	 */
	void (*set_option)(struct smc_bpf_ops_ctx *ctx);

	/* Invoked before Set up SMC options for SYN-ACK packets
	 * We can control whether to respond SMC options by modifying
	 * ctx->set_option_cond.smc_ok.
	 * Only member in ctx->set_option_cond is valid for this callback.
	 */
	void (*set_option_cond)(struct smc_bpf_ops_ctx *ctx);
};

#endif	/* _SMC_H */
