/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (c) 2022, MediaTek Inc.
 */

#ifndef __MTK_FSM_H__
#define __MTK_FSM_H__

#include <linux/mutex.h>

#include "mtk_dev.h"

#define FEATURE_CNT		(64)
#define FEATURE_QUERY_PATTERN	(0x49434343)

#define FEATURE_TYPE		GENMASK(3, 0)
#define FEATURE_VER		GENMASK(7, 4)

#define FEATURE_TYPE_NOT	FIELD_PREP(FEATURE_TYPE, RTFT_TYPE_NOT_SUPPORT)
#define FEATURE_TYPE_MUST	FIELD_PREP(FEATURE_TYPE, RTFT_TYPE_MUST_SUPPORT)
#define FEATURE_TYPE_OPTIONAL	FIELD_PREP(FEATURE_TYPE, RTFT_TYPE_OPTIONAL_SUPPORT)
#define FEATURE_VER_0		FIELD_PREP(FEATURE_VER, 0)

#define EVT_MODE_BLOCKING	(0x01)
#define EVT_MODE_TOHEAD		(0x02)

#define FSM_EVT_RET_FAIL	(-1)
#define FSM_EVT_RET_ONGOING	(0)
#define FSM_EVT_RET_DONE	(1)

enum mtk_fsm_flag {
	FSM_F_DFLT = 0,
	FSM_F_SAP_HS_START	= BIT(0),
	FSM_F_SAP_HS2_DONE	= BIT(1),
	FSM_F_MD_HS_START	= BIT(2),
	FSM_F_MD_HS2_DONE	= BIT(3),
};

enum mtk_fsm_state {
	FSM_STATE_INVALID = 0,
	FSM_STATE_OFF,
	FSM_STATE_ON,
	FSM_STATE_BOOTUP,
	FSM_STATE_READY,
};

enum mtk_fsm_evt_id {
	FSM_EVT_STARTUP = 0,
	FSM_EVT_DEV_RM,
	FSM_EVT_DEV_ADD,
	FSM_EVT_MAX
};

enum mtk_fsm_prio {
	FSM_PRIO_0 = 0,
	FSM_PRIO_1 = 1,
	FSM_PRIO_MAX
};

struct mtk_fsm_param {
	enum mtk_fsm_state from;
	enum mtk_fsm_state to;
	enum mtk_fsm_evt_id evt_id;
	enum mtk_fsm_flag fsm_flag;
};

#define PORT_NAME_LEN 20

enum handshake_info_id {
	HS_ID_MD = 0,
	HS_ID_SAP,
	HS_ID_MAX
};

struct runtime_feature_info {
	u8 feature;
};

struct fsm_hs_info {
	unsigned char id;
	void *ctrl_port;
	char port_name[PORT_NAME_LEN];
	unsigned int mhccif_ch;
	unsigned int fsm_flag_hs1;
	unsigned int fsm_flag_hs2;
	/* the feature that the device should support */
	struct runtime_feature_info query_ft_set[FEATURE_CNT];
	/* Duplicate-HS2 guard only: the in-flight runtime-data skb itself
	 * is owned by the STARTUP event it was submitted with.
	 */
	void *rt_data;
};

struct mtk_md_fsm {
	struct mtk_md_dev *mdev;
	struct task_struct *fsm_handler;
	struct fsm_hs_info hs_info[HS_ID_MAX];
	unsigned int hs_done_flag;
	unsigned long t_flag;
	u32 last_dev_state;
	/* first transport-plane init failure; refuses READY until DEV_ADD */
	int hif_err;
	enum mtk_fsm_state state;
	unsigned int fsm_flag;
	struct list_head evtq;
	/* protect evtq */
	spinlock_t evtq_lock;
	/* waitq for fsm blocking submit */
	wait_queue_head_t evt_waitq;
	struct list_head pre_notifiers;
	struct list_head post_notifiers;
	/* protects pre_notifiers and post_notifiers lists */
	struct mutex notifier_lock;
};

struct mtk_fsm_evt {
	struct list_head entry;
	struct kref kref;
	struct mtk_md_dev *mdev;
	enum mtk_fsm_evt_id id;
	unsigned int fsm_flag;
	int status;
	unsigned char mode;
	unsigned int len;
	void *data;
};

struct mtk_fsm_notifier {
	struct list_head entry;
	enum mtk_user_id id;
	void (*cb)(struct mtk_fsm_param *param, void *data);
	void *data;
	enum mtk_fsm_prio prio;
};

int mtk_fsm_init(struct mtk_md_dev *mdev);
int mtk_fsm_exit(struct mtk_md_dev *mdev);
int mtk_fsm_start(struct mtk_md_dev *mdev);
int mtk_fsm_stop(struct mtk_md_dev *mdev);
void mtk_fsm_hif_err_record(struct mtk_md_dev *mdev, int err);
int mtk_fsm_notifier_register(struct mtk_md_dev *mdev, enum mtk_user_id id,
			      void (*cb)(struct mtk_fsm_param *, void *data),
			      void *data, enum mtk_fsm_prio prio, bool is_pre);
int mtk_fsm_notifier_unregister(struct mtk_md_dev *mdev, enum mtk_user_id id);
int mtk_fsm_evt_submit(struct mtk_md_dev *mdev,
		       enum mtk_fsm_evt_id id, enum mtk_fsm_flag flag,
		       void *data, unsigned int len, unsigned char mode);

#endif /* __MTK_FSM_H__ */
