// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022, MediaTek Inc.
 */

#include <linux/bitfield.h>
#include <linux/device.h>
#include <linux/kref.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/pci.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/skbuff.h>
#include <linux/wait.h>

#include "mtk_fsm.h"
#include "mtk_port.h"
#include "mtk_port_io.h"
#include "mtk_utility.h"

#define EVT_TF_GATECLOSED (1)
#define MTK_FSM_INFO_LEN	(64)

#define FSM_HS_START_MASK	(FSM_F_SAP_HS_START | FSM_F_MD_HS_START)
#define FSM_HS2_DONE_MASK	(FSM_F_SAP_HS2_DONE | FSM_F_MD_HS2_DONE)

#define RTFT_DATA_SIZE		(3 * 1024)
#define EVT_HANDLER_TIMEOUT	(HZ * 30)
#define BLOCKING_EVT_TIMEOUT	(2 * EVT_HANDLER_TIMEOUT)

#define REGION_BITMASK		0xF
#define DEVICE_CFG_SHIFT	24
#define DEVICE_CFG_REGION_MASK	0x3

enum device_stage {
	DEV_STAGE_IDLE = 4,
	DEV_STAGE_MAX
};

enum device_cfg {
	DEV_CFG_NORMAL = 0,
	DEV_CFG_MD_ONLY,
};

enum runtime_feature_support_type {
	RTFT_TYPE_NOT_EXIST = 0,
	RTFT_TYPE_NOT_SUPPORT = 1,
	RTFT_TYPE_MUST_SUPPORT = 2,
	RTFT_TYPE_OPTIONAL_SUPPORT = 3,
	RTFT_TYPE_SUPPORT_BACKWARD_COMPAT = 4,
};

enum query_runtime_feature_id {
	QUERY_RTFT_ID_MD_PORT_ENUM = 0,
	QUERY_RTFT_ID_SAP_PORT_ENUM = 1,
	QUERY_RTFT_ID_MD_PORT_CFG = 2,
	QUERY_RTFT_ID_MAX
};

enum ctrl_msg_id {
	CTRL_MSG_HS1 = 0,
	CTRL_MSG_HS2 = 1,
	CTRL_MSG_HS3 = 2,
};

struct ctrl_msg_header {
	__le32 id;
	__le32 ex_msg;
	__le32 data_len;
	u8 reserved[];
} __packed;

struct runtime_feature_entry {
	u8 feature_id;
	struct runtime_feature_info support_info;
	u8 reserved[2];
	__le32 data_len;
	u8 data[];
};

struct feature_query {
	__le32 head_pattern;
	struct runtime_feature_info ft_set[FEATURE_CNT];
	__le32 tail_pattern;
};

static int mtk_fsm_send_hs1_msg(struct fsm_hs_info *hs_info)
{
	struct ctrl_msg_header *ctrl_msg_h;
	struct feature_query *ft_query;
	struct sk_buff *skb;
	int ret, msg_size;

	msg_size = sizeof(*ctrl_msg_h) + sizeof(*ft_query);
	skb = __dev_alloc_skb(msg_size, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	skb_put(skb, msg_size);
	ctrl_msg_h = (struct ctrl_msg_header *)skb->data;
	ctrl_msg_h->id = cpu_to_le32(CTRL_MSG_HS1);
	ctrl_msg_h->ex_msg = 0;
	ctrl_msg_h->data_len = cpu_to_le32(sizeof(*ft_query));

	ft_query = (struct feature_query *)(skb->data + sizeof(*ctrl_msg_h));
	ft_query->head_pattern = cpu_to_le32(FEATURE_QUERY_PATTERN);
	memcpy(ft_query->ft_set, hs_info->query_ft_set, sizeof(hs_info->query_ft_set));
	ft_query->tail_pattern = cpu_to_le32(FEATURE_QUERY_PATTERN);

	/* send handshake1 message to device */
	ret = mtk_port_internal_write(hs_info->ctrl_port, skb);
	if (ret <= 0)
		return ret;

	return 0;
}

static int mtk_fsm_feature_set_match(enum runtime_feature_support_type *cur_ft_spt,
				     struct runtime_feature_info rtft_info_st,
				     struct runtime_feature_info rtft_info_cfg)
{
	int ret = 0;

	switch (FIELD_GET(FEATURE_TYPE, rtft_info_st.feature)) {
	case RTFT_TYPE_NOT_EXIST:
		fallthrough;
	case RTFT_TYPE_NOT_SUPPORT:
		/* The device refusing a feature the host declared mandatory
		 * must fail the handshake, symmetrically with the
		 * MUST_SUPPORT case below.
		 */
		if (FIELD_GET(FEATURE_TYPE, rtft_info_cfg.feature) == RTFT_TYPE_MUST_SUPPORT)
			ret = -EPROTO;
		else
			*cur_ft_spt = RTFT_TYPE_NOT_EXIST;
		break;
	case RTFT_TYPE_MUST_SUPPORT:
		if (FIELD_GET(FEATURE_TYPE, rtft_info_cfg.feature) == RTFT_TYPE_NOT_EXIST ||
		    FIELD_GET(FEATURE_TYPE, rtft_info_cfg.feature) == RTFT_TYPE_NOT_SUPPORT)
			ret = -EPROTO;
		else
			*cur_ft_spt = RTFT_TYPE_MUST_SUPPORT;
		break;
	case RTFT_TYPE_OPTIONAL_SUPPORT:
		if (FIELD_GET(FEATURE_TYPE, rtft_info_cfg.feature) == RTFT_TYPE_NOT_EXIST ||
		    FIELD_GET(FEATURE_TYPE, rtft_info_cfg.feature) == RTFT_TYPE_NOT_SUPPORT) {
			*cur_ft_spt = RTFT_TYPE_NOT_SUPPORT;
		} else {
			if (FIELD_GET(FEATURE_VER, rtft_info_st.feature) ==
			    FIELD_GET(FEATURE_VER, rtft_info_cfg.feature))
				*cur_ft_spt = RTFT_TYPE_MUST_SUPPORT;
			else
				*cur_ft_spt = RTFT_TYPE_NOT_SUPPORT;
		}
		break;
	case RTFT_TYPE_SUPPORT_BACKWARD_COMPAT:
		if (FIELD_GET(FEATURE_VER, rtft_info_st.feature) >=
		    FIELD_GET(FEATURE_VER, rtft_info_cfg.feature))
			*cur_ft_spt = RTFT_TYPE_MUST_SUPPORT;
		else
			*cur_ft_spt = RTFT_TYPE_NOT_EXIST;
		break;
	default:
		ret = -EPROTO;
	}

	return ret;
}

static int (*query_rtft_action[FEATURE_CNT])(struct mtk_md_dev *mdev,
					     void *rt_data, u32 data_len) = {
	[QUERY_RTFT_ID_MD_PORT_ENUM] = mtk_port_status_update,
	[QUERY_RTFT_ID_SAP_PORT_ENUM] = mtk_port_status_update,
};

/* The runtime data skb is owned by the caller (the FSM kthread, which got
 * it attached to the STARTUP event); its pointer and length are read once
 * from the skb itself, never from a shared field the rx path could rewrite.
 */
static int mtk_fsm_parse_hs2_msg(struct mtk_md_fsm *fsm, struct fsm_hs_info *hs_info,
				 struct sk_buff *skb)
{
	enum runtime_feature_support_type cur_ft_spt;
	struct runtime_feature_entry *rtft_entry;
	unsigned int ft_id, offset, data_len;
	unsigned int rt_data_len;
	char *rt_data;
	int ret = 0;

	if (!skb)
		return -EINVAL;

	rt_data = skb->data;
	rt_data_len = skb->len;

	offset = sizeof(struct feature_query);
	for (ft_id = 0; ft_id < FEATURE_CNT; ft_id++) {
		if (offset + sizeof(*rtft_entry) > rt_data_len)
			break;

		rtft_entry = (struct runtime_feature_entry *)(rt_data + offset);
		ret = mtk_fsm_feature_set_match(&cur_ft_spt,
						rtft_entry->support_info,
						hs_info->query_ft_set[ft_id]);
		if (ret < 0)
			break;

		data_len = le32_to_cpu(rtft_entry->data_len);
		if (data_len > rt_data_len - offset - sizeof(*rtft_entry))
			break;

		if (cur_ft_spt == RTFT_TYPE_MUST_SUPPORT && query_rtft_action[ft_id]) {
			if (!data_len) {
				dev_err(fsm->mdev->dev,
					"RTFT feature %u: zero data_len\n", ft_id);
				ret = -EPROTO;
				break;
			}
			ret = query_rtft_action[ft_id](fsm->mdev,
						       rtft_entry->data,
						       data_len);
		}
		if (ret < 0)
			break;

		offset += sizeof(*rtft_entry) + data_len;
	}

	if (ft_id != FEATURE_CNT) {
		dev_err((fsm->mdev)->dev, "Unable to handle mistake hs2 msg, ft_id=%d\n", ft_id);
		ret = -EPROTO;
	}

	return ret;
}

static int mtk_fsm_append_rtft_entries(struct mtk_md_dev *mdev, void *feature_data,
				       unsigned int *len, struct fsm_hs_info *hs_info,
				       struct sk_buff *skb)
{
	struct runtime_feature_entry *rtft_entry;
	int ft_id, ret = 0, rtdata_len = 0;
	struct feature_query *ft_query;

	if (!skb || skb->len < sizeof(*ft_query)) {
		ret = -EPROTO;
		goto hs_err;
	}

	ft_query = (struct feature_query *)skb->data;
	if (le32_to_cpu(ft_query->head_pattern) != FEATURE_QUERY_PATTERN ||
	    le32_to_cpu(ft_query->tail_pattern) != FEATURE_QUERY_PATTERN) {
		ret = -EPROTO;
		goto hs_err;
	}

	/* parse runtime feature query and fill runtime feature entry */
	rtft_entry = feature_data;
	for (ft_id = 0; ft_id < FEATURE_CNT && rtdata_len < RTFT_DATA_SIZE; ft_id++) {
		rtft_entry->feature_id = ft_id;
		rtft_entry->data_len = 0;

		switch (FIELD_GET(FEATURE_TYPE, ft_query->ft_set[ft_id].feature)) {
		case RTFT_TYPE_NOT_EXIST:
			fallthrough;
		case RTFT_TYPE_NOT_SUPPORT:
			fallthrough;
		case RTFT_TYPE_MUST_SUPPORT:
			rtft_entry->support_info = ft_query->ft_set[ft_id];
			break;
		case RTFT_TYPE_OPTIONAL_SUPPORT:
			fallthrough;
		case RTFT_TYPE_SUPPORT_BACKWARD_COMPAT:
			rtft_entry->support_info.feature = FEATURE_TYPE_NOT;
			rtft_entry->support_info.feature |= FEATURE_VER_0;
			break;
		}

		rtdata_len += sizeof(*rtft_entry) + le32_to_cpu(rtft_entry->data_len);
		rtft_entry = (struct runtime_feature_entry *)(feature_data + rtdata_len);
	}
	*len = rtdata_len;
	return 0;

hs_err:
	*len = 0;
	return ret;
}

static int mtk_fsm_send_hs3_msg(struct fsm_hs_info *hs_info, struct sk_buff *rt_skb)
{
	struct mtk_md_fsm *fsm = container_of(hs_info, struct mtk_md_fsm, hs_info[hs_info->id]);
	unsigned int data_len, msg_size = 0;
	struct ctrl_msg_header *ctrl_msg_h;
	struct sk_buff *skb;
	int ret;

	skb = __dev_alloc_skb(RTFT_DATA_SIZE, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;
	memset(skb->data, 0, RTFT_DATA_SIZE);

	msg_size += sizeof(*ctrl_msg_h);
	ctrl_msg_h = (struct ctrl_msg_header *)skb->data;
	ctrl_msg_h->id = cpu_to_le32(CTRL_MSG_HS3);
	ctrl_msg_h->ex_msg = 0;
	ret = mtk_fsm_append_rtft_entries(fsm->mdev,
					  skb->data + sizeof(*ctrl_msg_h),
					  &data_len, hs_info, rt_skb);
	if (ret) {
		dev_kfree_skb(skb);
		return ret;
	}

	ctrl_msg_h->data_len = cpu_to_le32(data_len);
	msg_size += data_len;
	skb_put(skb, msg_size);
	ret = mtk_port_internal_write(hs_info->ctrl_port, skb);
	if (ret <= 0)
		return ret;

	return 0;
}

/* Both handlers own the skb on every path and always return 0: the caller
 * (mtk_port_rx_dispatch) frees the skb itself on a negative return, so
 * returning an error after dev_kfree_skb() would free it twice.
 *
 * On success the skb is attached to the submitted event (event->data) and
 * from then on belongs to the FSM kthread; hs_info->rt_data is kept only
 * as the duplicate-HS2 guard and is cleared by the kthread once the event
 * has been consumed.  That store and the accesses below are the only
 * concurrent users of the field, so they are marked: a stale non-NULL read
 * at worst drops one retransmitted HS2, which the device repeats.
 */
static int mtk_fsm_sap_ctrl_msg_handler(void *__fsm, struct sk_buff *skb)
{
	struct ctrl_msg_header *ctrl_msg_h;
	struct mtk_md_fsm *fsm = __fsm;
	struct fsm_hs_info *hs_info;
	int ret;

	if (skb->len < sizeof(*ctrl_msg_h)) {
		dev_kfree_skb(skb);
		return 0;
	}

	ctrl_msg_h = (struct ctrl_msg_header *)skb->data;
	skb_pull(skb, sizeof(*ctrl_msg_h));

	hs_info = &fsm->hs_info[HS_ID_SAP];
	if (le32_to_cpu(ctrl_msg_h->id) != CTRL_MSG_HS2) {
		dev_err(fsm->mdev->dev, "Invalid SAP ctrl msg id\n");
		dev_kfree_skb(skb);
		return 0;
	}

	if (READ_ONCE(hs_info->rt_data)) {
		dev_warn(fsm->mdev->dev, "Duplicate SAP HS2, dropping\n");
		dev_kfree_skb(skb);
		return 0;
	}

	WRITE_ONCE(hs_info->rt_data, skb);
	ret = mtk_fsm_evt_submit(fsm->mdev, FSM_EVT_STARTUP,
				 hs_info->fsm_flag_hs2, skb, skb->len, 0);
	if (ret == FSM_EVT_RET_FAIL) {
		WRITE_ONCE(hs_info->rt_data, NULL);
		dev_kfree_skb(skb);
	}

	return 0;
}

static int mtk_fsm_md_ctrl_msg_handler(void *__fsm, struct sk_buff *skb)
{
	struct ctrl_msg_header *ctrl_msg_h;
	struct mtk_md_fsm *fsm = __fsm;
	struct fsm_hs_info *hs_info;
	int ret;

	if (skb->len < sizeof(*ctrl_msg_h)) {
		dev_kfree_skb(skb);
		return 0;
	}

	ctrl_msg_h = (struct ctrl_msg_header *)skb->data;
	hs_info = &fsm->hs_info[HS_ID_MD];
	if (le32_to_cpu(ctrl_msg_h->id) != CTRL_MSG_HS2) {
		dev_err(fsm->mdev->dev, "Invalid ctrl msg id\n");
		dev_kfree_skb(skb);
		return 0;
	}

	if (READ_ONCE(hs_info->rt_data)) {
		/* The guarded skb belongs to a still-queued event; only the
		 * new skb may be freed here.
		 */
		dev_warn(fsm->mdev->dev, "Duplicate MD HS2, dropping\n");
		dev_kfree_skb(skb);
		return 0;
	}

	skb_pull(skb, sizeof(*ctrl_msg_h));
	WRITE_ONCE(hs_info->rt_data, skb);
	ret = mtk_fsm_evt_submit(fsm->mdev, FSM_EVT_STARTUP,
				 hs_info->fsm_flag_hs2, skb, skb->len, 0);
	if (ret == FSM_EVT_RET_FAIL) {
		WRITE_ONCE(hs_info->rt_data, NULL);
		dev_kfree_skb(skb);
	}

	return 0;
}

static int (*ctrl_msg_handler[HS_ID_MAX])(void *__fsm, struct sk_buff *skb) = {
	[HS_ID_MD] = mtk_fsm_md_ctrl_msg_handler,
	[HS_ID_SAP] = mtk_fsm_sap_ctrl_msg_handler,
};

static int mtk_fsm_idle_evt_handler(struct mtk_md_dev *mdev,
				    u32 dev_state, struct mtk_md_fsm *fsm)
{
	u32 dev_cfg = dev_state >> DEVICE_CFG_SHIFT & DEVICE_CFG_REGION_MASK;
	int hs_id;

	if (dev_cfg == DEV_CFG_MD_ONLY)
		fsm->hs_done_flag = FSM_F_MD_HS_START | FSM_F_MD_HS2_DONE;
	else
		fsm->hs_done_flag = FSM_HS_START_MASK | FSM_HS2_DONE_MASK;

	/* On failure keep the handshake channels masked and report it, so
	 * the device's next boot-flow notification can retrigger us.
	 */
	if (mtk_fsm_evt_submit(mdev, FSM_EVT_STARTUP, FSM_F_DFLT,
			       NULL, 0, 0) == FSM_EVT_RET_FAIL) {
		dev_err(mdev->dev, "Failed to submit STARTUP evt, waiting for retry\n");
		return -ENOMEM;
	}

	for (hs_id = 0; hs_id < HS_ID_MAX; hs_id++)
		mtk_dev_unmask_dev_evt(mdev, fsm->hs_info[hs_id].mhccif_ch);

	return 0;
}

static int mtk_fsm_early_bootup_handler(u32 status, void *__fsm)
{
	struct mtk_md_fsm *fsm = __fsm;
	struct mtk_md_dev *mdev;
	u32 dev_state, dev_stage;

	mdev = fsm->mdev;
	mtk_dev_mask_dev_evt(mdev, status);
	mtk_dev_clear_dev_evt(mdev, status);

	dev_state = mtk_dev_get_dev_state(mdev);
	dev_stage = dev_state & REGION_BITMASK;
	if (dev_stage >= DEV_STAGE_MAX) {
		dev_err(mdev->dev, "Invalid dev state 0x%x\n", dev_state);
		return -ENXIO;
	}

	if (dev_state == fsm->last_dev_state)
		goto exit;

	/* Only latch the state once it has been acted on; a failed submit
	 * leaves last_dev_state unchanged so the repeated notification is
	 * not filtered out.
	 */
	if (dev_stage == DEV_STAGE_IDLE &&
	    mtk_fsm_idle_evt_handler(mdev, dev_state, fsm))
		goto exit;

	fsm->last_dev_state = dev_state;

exit:
	/* Re-arm the channel masked on entry: the device notifies once
	 * per boot stage, so leaving it masked drops every later stage.
	 * A device still booting when the driver binds would never
	 * deliver its DEV_STAGE_IDLE notification, and a STARTUP submit
	 * that failed above would never see a second one to retry on.
	 */
	mtk_dev_unmask_dev_evt(mdev, status);
	return 0;
}

static int mtk_fsm_ctrl_ch_start(struct mtk_md_fsm *fsm, struct fsm_hs_info *hs_info, int flag)
{
	if (!hs_info->ctrl_port) {
		hs_info->ctrl_port = mtk_port_internal_open(fsm->mdev, hs_info->port_name, flag);
		if (!hs_info->ctrl_port) {
			dev_err(fsm->mdev->dev, "Failed to open ctrl port(%s)\n",
				hs_info->port_name);
			return -ENODEV;
		}

		mtk_port_internal_recv_register(hs_info->ctrl_port,
						ctrl_msg_handler[hs_info->id], fsm);
	}

	return 0;
}

static void mtk_fsm_ctrl_ch_stop(struct mtk_md_fsm *fsm)
{
	struct fsm_hs_info *hs_info;
	int hs_id;

	for (hs_id = 0; hs_id < HS_ID_MAX; hs_id++) {
		hs_info = &fsm->hs_info[hs_id];
		if (hs_info->ctrl_port) {
			mtk_port_internal_close(hs_info->ctrl_port);
			hs_info->ctrl_port = NULL;
		}
	}
}

static void mtk_fsm_switch_state(struct mtk_md_fsm *fsm,
				 enum mtk_fsm_state to_state, struct mtk_fsm_evt *event)
{
	char fsm_info[MTK_FSM_INFO_LEN];
	struct mtk_fsm_notifier *nt;
	struct mtk_fsm_param param;

	param.from = fsm->state;
	param.to = to_state;
	param.evt_id = event ? event->id : FSM_EVT_MAX;
	param.fsm_flag = event ? event->fsm_flag : FSM_F_DFLT;

	mutex_lock(&fsm->notifier_lock);
	list_for_each_entry(nt, &fsm->pre_notifiers, entry)
		nt->cb(&param, nt->data);

	fsm->state = to_state;
	fsm->fsm_flag |= event ? event->fsm_flag : FSM_F_DFLT;

	snprintf(fsm_info, MTK_FSM_INFO_LEN,
		 "state=%d, fsm_flag=0x%x", to_state, fsm->fsm_flag);
	mtk_uevent_notify(fsm->mdev->dev, MTK_UEVENT_FSM, fsm_info);

	list_for_each_entry(nt, &fsm->post_notifiers, entry)
		nt->cb(&param, nt->data);
	mutex_unlock(&fsm->notifier_lock);
}

static int mtk_fsm_startup_act(struct mtk_md_fsm *fsm, struct mtk_fsm_evt *event)
{
	enum mtk_fsm_state to_state = FSM_STATE_BOOTUP;
	struct mtk_md_dev *mdev = fsm->mdev;
	struct fsm_hs_info *hs_info;
	struct sk_buff *skb = NULL;
	int ret = 0;

	if (event->fsm_flag & FSM_HS2_DONE_MASK) {
		/* The HS2 event owns its runtime-data skb. */
		skb = event->data;
		hs_info = &fsm->hs_info[(event->fsm_flag & FSM_F_MD_HS2_DONE) ?
					HS_ID_MD : HS_ID_SAP];
	} else {
		/* HS1 events carry the hs_info; the bare STARTUP carries NULL. */
		hs_info = event->data;
	}

	if (fsm->state != FSM_STATE_ON && fsm->state != FSM_STATE_BOOTUP) {
		ret = -EPROTO;
		goto free_skb;
	}

	if (!(event->fsm_flag & (FSM_HS_START_MASK | FSM_HS2_DONE_MASK))) {
		/* Bare STARTUP from the boot-flow notification: only the
		 * state switch.
		 */
		if (fsm->state != FSM_STATE_BOOTUP)
			mtk_fsm_switch_state(fsm, to_state, event);
		return 0;
	}

	if (event->fsm_flag & FSM_HS_START_MASK) {
		/* An HS1 that raced ahead of the bare STARTUP must both
		 * switch ON to BOOTUP and run the handshake below; returning
		 * after the switch would consume the only trigger.
		 */
		mtk_fsm_switch_state(fsm, to_state, event);

		ret = mtk_fsm_ctrl_ch_start(fsm, hs_info, O_NONBLOCK);
		if (!ret)
			ret = mtk_fsm_send_hs1_msg(hs_info);
		if (ret)
			goto hs_err;
	} else if (event->fsm_flag & FSM_HS2_DONE_MASK) {
		ret = mtk_fsm_parse_hs2_msg(fsm, hs_info, skb);
		if (!ret)
			ret = mtk_fsm_send_hs3_msg(hs_info, skb);
		dev_kfree_skb(skb);
		skb = NULL;
		/* re-open the duplicate guard */
		WRITE_ONCE(hs_info->rt_data, NULL);
		if (ret)
			goto hs_err;
		mtk_fsm_switch_state(fsm, to_state, event);
	}

	if (((fsm->fsm_flag | event->fsm_flag) & fsm->hs_done_flag) == fsm->hs_done_flag) {
		if (fsm->hif_err) {
			dev_err(mdev->dev,
				"Refusing READY: HIF init failed with %d\n",
				fsm->hif_err);
			return fsm->hif_err;
		}
		to_state = FSM_STATE_READY;
		mtk_fsm_switch_state(fsm, to_state, NULL);
	}

	return 0;

free_skb:
	if (skb) {
		dev_kfree_skb(skb);
		WRITE_ONCE(hs_info->rt_data, NULL);
	}
hs_err:
	for (int hs_id = 0; hs_id < HS_ID_MAX; hs_id++)
		mtk_dev_unmask_dev_evt(mdev, fsm->hs_info[hs_id].mhccif_ch);
	dev_err(mdev->dev, "Failed to hs with device %d:0x%x, ret=%d",
		fsm->state, fsm->fsm_flag, ret);
	return ret;
}

static void mtk_fsm_evt_release(struct kref *kref)
{
	struct mtk_fsm_evt *event = container_of(kref, struct mtk_fsm_evt, kref);

	kfree(event);
}

static void mtk_fsm_evt_put(struct mtk_fsm_evt *event)
{
	kref_put(&event->kref, mtk_fsm_evt_release);
}

static void mtk_fsm_evt_finish(struct mtk_md_fsm *fsm,
			       struct mtk_fsm_evt *event, int retval)
{
	if (event->mode & EVT_MODE_BLOCKING) {
		event->status = retval;
		wake_up(&fsm->evt_waitq);
	}
	mtk_fsm_evt_put(event);
}

static void mtk_fsm_evt_cleanup(struct mtk_md_fsm *fsm, struct list_head *evtq)
{
	struct mtk_fsm_evt *event, *tmp;

	list_for_each_entry_safe(event, tmp, evtq, entry) {
		list_del(&event->entry);
		mtk_fsm_evt_finish(fsm, event, FSM_EVT_RET_FAIL);
	}
}

static int mtk_fsm_enter_off_state(struct mtk_md_fsm *fsm, struct mtk_fsm_evt *event)
{
	struct mtk_md_dev *mdev = fsm->mdev;
	int hs_id;

	if (fsm->state == FSM_STATE_OFF || fsm->state == FSM_STATE_INVALID)
		return -EPROTO;

	mtk_dev_mask_dev_evt(mdev, DEV_EVT_D2H_BOOT_FLOW_SYNC);
	for (hs_id = 0; hs_id < HS_ID_MAX; hs_id++)
		mtk_dev_mask_dev_evt(mdev, fsm->hs_info[hs_id].mhccif_ch);

	mtk_fsm_ctrl_ch_stop(fsm);
	mtk_fsm_switch_state(fsm, FSM_STATE_OFF, event);

	return 0;
}

static int mtk_fsm_dev_rm_act(struct mtk_md_fsm *fsm, struct mtk_fsm_evt *event)
{
	unsigned long flags;

	spin_lock_irqsave(&fsm->evtq_lock, flags);
	set_bit(EVT_TF_GATECLOSED, &fsm->t_flag);
	mtk_fsm_evt_cleanup(fsm, &fsm->evtq);
	spin_unlock_irqrestore(&fsm->evtq_lock, flags);

	return mtk_fsm_enter_off_state(fsm, event);
}

static int mtk_fsm_hs1_handler(u32 status, void *__hs_info)
{
	struct fsm_hs_info *hs_info = __hs_info;
	struct mtk_md_dev *mdev;
	struct mtk_md_fsm *fsm;

	fsm = container_of(hs_info, struct mtk_md_fsm, hs_info[hs_info->id]);
	mdev = fsm->mdev;
	/* Only consume the notification once the event is queued; on a
	 * failed submit the channel stays unmasked and uncleared so the
	 * device's retry still reaches us.
	 */
	if (mtk_fsm_evt_submit(mdev, FSM_EVT_STARTUP, hs_info->fsm_flag_hs1,
			       hs_info, sizeof(*hs_info), 0) == FSM_EVT_RET_FAIL) {
		dev_err(mdev->dev, "Failed to submit HS1 evt(hs%d), waiting for retry\n",
			hs_info->id);
		return -ENOMEM;
	}
	mtk_dev_mask_dev_evt(mdev, hs_info->mhccif_ch);
	mtk_dev_clear_dev_evt(mdev, hs_info->mhccif_ch);

	return 0;
}

static void mtk_fsm_hs_info_init_by_hsid(struct mtk_md_fsm *fsm, int hs_id)
{
	struct fsm_hs_info *hs_info;

	if (hs_id < 0 || hs_id >= HS_ID_MAX) {
		dev_warn((fsm->mdev)->dev, "hs_id = %d, invalid.\n", hs_id);
		return;
	}

	hs_info = &fsm->hs_info[hs_id];
	hs_info->id = hs_id;
	hs_info->ctrl_port = NULL;
	hs_info->rt_data = NULL;
	switch (hs_id) {
	case HS_ID_MD:
		snprintf(hs_info->port_name, PORT_NAME_LEN, "MDCTRL");
		hs_info->mhccif_ch = DEV_EVT_D2H_ASYNC_HS_NOTIFY_MD;
		hs_info->fsm_flag_hs1 = FSM_F_MD_HS_START;
		hs_info->fsm_flag_hs2 = FSM_F_MD_HS2_DONE;
		hs_info->query_ft_set[QUERY_RTFT_ID_MD_PORT_ENUM].feature =
			FIELD_PREP(FEATURE_TYPE, RTFT_TYPE_MUST_SUPPORT);
		hs_info->query_ft_set[QUERY_RTFT_ID_MD_PORT_ENUM].feature |=
			FIELD_PREP(FEATURE_VER, 0);
		hs_info->query_ft_set[QUERY_RTFT_ID_MD_PORT_CFG].feature =
			FIELD_PREP(FEATURE_TYPE, RTFT_TYPE_NOT_SUPPORT);
		break;
	case HS_ID_SAP:
		snprintf(hs_info->port_name, PORT_NAME_LEN, "SAPCTRL");
		hs_info->mhccif_ch = DEV_EVT_D2H_ASYNC_HS_NOTIFY_SAP;
		hs_info->fsm_flag_hs1 = FSM_F_SAP_HS_START;
		hs_info->fsm_flag_hs2 = FSM_F_SAP_HS2_DONE;
		hs_info->query_ft_set[QUERY_RTFT_ID_SAP_PORT_ENUM].feature =
			FIELD_PREP(FEATURE_TYPE, RTFT_TYPE_MUST_SUPPORT);
		hs_info->query_ft_set[QUERY_RTFT_ID_SAP_PORT_ENUM].feature |=
			FIELD_PREP(FEATURE_VER, 0);
		break;
	}
}

static int mtk_fsm_hs_info_init(struct mtk_md_fsm *fsm)
{
	struct mtk_md_dev *mdev = fsm->mdev;
	struct fsm_hs_info *hs_info;
	int hs_id, ret;

	for (hs_id = 0; hs_id < HS_ID_MAX; hs_id++) {
		mtk_fsm_hs_info_init_by_hsid(fsm, hs_id);
		hs_info = &fsm->hs_info[hs_id];
		ret = mtk_dev_register_dev_evt(mdev, hs_info->mhccif_ch,
					       mtk_fsm_hs1_handler, hs_info);
		if (ret)
			goto err_unregister;
	}

	return 0;

err_unregister:
	/* All or nothing: the caller must not have to know how far we got. */
	while (--hs_id >= 0)
		mtk_dev_unregister_dev_evt(mdev, fsm->hs_info[hs_id].mhccif_ch);

	return ret;
}

static void mtk_fsm_hs_info_exit(struct mtk_md_fsm *fsm)
{
	struct mtk_md_dev *mdev = fsm->mdev;
	struct fsm_hs_info *hs_info;
	int hs_id;

	for (hs_id = 0; hs_id < HS_ID_MAX; hs_id++) {
		hs_info = &fsm->hs_info[hs_id];
		mtk_dev_unregister_dev_evt(mdev, hs_info->mhccif_ch);
	}
}

static int mtk_fsm_dev_add_act(struct mtk_md_fsm *fsm, struct mtk_fsm_evt *event)
{
	if (fsm->state != FSM_STATE_OFF && fsm->state != FSM_STATE_INVALID)
		return -EPROTO;

	/* a fresh device lifecycle starts with a clean HIF error record */
	fsm->hif_err = 0;
	mtk_fsm_switch_state(fsm, FSM_STATE_ON, event);
	mtk_dev_unmask_dev_evt(fsm->mdev, DEV_EVT_D2H_BOOT_FLOW_SYNC);

	return 0;
}

static int (*evts_act_tbl[FSM_EVT_MAX])(struct mtk_md_fsm *__fsm, struct mtk_fsm_evt *event) = {
	[FSM_EVT_STARTUP] = mtk_fsm_startup_act,
	[FSM_EVT_DEV_RM] = mtk_fsm_dev_rm_act,
	[FSM_EVT_DEV_ADD] = mtk_fsm_dev_add_act,
};

int mtk_fsm_start(struct mtk_md_dev *mdev)
{
	struct mtk_md_fsm *fsm = mdev->fsm;

	if (!fsm)
		return -EINVAL;

	if (!fsm->fsm_handler)
		return -EFAULT;

	wake_up_process(fsm->fsm_handler);
	return 0;
}
EXPORT_SYMBOL_GPL(mtk_fsm_start);

/* Record a transport-plane init failure so the STARTUP path refuses the
 * BOOTUP-to-READY promotion: the notifier callbacks are void and cannot
 * reject a transition, so without this the FSM would advertise readiness
 * on top of a data path that was never created.  Cleared on DEV_ADD.
 */
void mtk_fsm_hif_err_record(struct mtk_md_dev *mdev, int err)
{
	struct mtk_md_fsm *fsm = mdev->fsm;

	if (fsm && !fsm->hif_err)
		fsm->hif_err = err;
}
EXPORT_SYMBOL_GPL(mtk_fsm_hif_err_record);

static void mkt_fsm_notifier_cleanup(struct mtk_md_dev *mdev, struct list_head *ntq)
{
	struct mtk_fsm_notifier *nt, *tmp;

	list_for_each_entry_safe(nt, tmp, ntq, entry) {
		list_del(&nt->entry);
		dev_warn(mdev->dev, "Having to free notifier(%d) by FSM!\n", nt->id);
		kfree(nt);
	}
}

static void mtk_fsm_notifier_insert(struct mtk_fsm_notifier *notifier, struct list_head *head)
{
	struct mtk_fsm_notifier *nt;

	list_for_each_entry(nt, head, entry) {
		if (notifier->prio > nt->prio) {
			list_add(&notifier->entry, nt->entry.prev);
			return;
		}
	}
	list_add_tail(&notifier->entry, head);
}

int mtk_fsm_notifier_register(struct mtk_md_dev *mdev, enum mtk_user_id id,
			      void (*cb)(struct mtk_fsm_param *, void *data),
			      void *data, enum mtk_fsm_prio prio, bool is_pre)
{
	struct mtk_md_fsm *fsm = mdev->fsm;
	struct mtk_fsm_notifier *notifier;

	if (!fsm)
		return -EINVAL;

	if (id >= MTK_USER_MAX || !cb || prio >= FSM_PRIO_MAX)
		return -EINVAL;

	notifier = kzalloc_obj(*notifier);
	if (!notifier)
		return -ENOMEM;

	INIT_LIST_HEAD(&notifier->entry);
	notifier->id = id;
	notifier->cb = cb;
	notifier->data = data;
	notifier->prio = prio;

	mutex_lock(&fsm->notifier_lock);
	if (is_pre)
		mtk_fsm_notifier_insert(notifier, &fsm->pre_notifiers);
	else
		mtk_fsm_notifier_insert(notifier, &fsm->post_notifiers);
	mutex_unlock(&fsm->notifier_lock);

	return 0;
}

int mtk_fsm_notifier_unregister(struct mtk_md_dev *mdev, enum mtk_user_id id)
{
	struct mtk_md_fsm *fsm = mdev->fsm;
	struct mtk_fsm_notifier *nt, *tmp;

	if (!fsm)
		return -EINVAL;

	mutex_lock(&fsm->notifier_lock);
	list_for_each_entry_safe(nt, tmp, &fsm->pre_notifiers, entry) {
		if (nt->id == id) {
			list_del(&nt->entry);
			kfree(nt);
			break;
		}
	}
	list_for_each_entry_safe(nt, tmp, &fsm->post_notifiers, entry) {
		if (nt->id == id) {
			list_del(&nt->entry);
			kfree(nt);
			break;
		}
	}
	mutex_unlock(&fsm->notifier_lock);
	return 0;
}

int mtk_fsm_evt_submit(struct mtk_md_dev *mdev,
		       enum mtk_fsm_evt_id id, enum mtk_fsm_flag flag,
		       void *data, unsigned int len, unsigned char mode)
{
	struct mtk_md_fsm *fsm = mdev->fsm;
	struct mtk_fsm_evt *event;
	unsigned long flags;
	int ret = 0;

	if (!fsm || id >= FSM_EVT_MAX) {
		dev_err(mdev->dev, "Invalid param!\n");
		return FSM_EVT_RET_FAIL;
	}

	if (test_bit(EVT_TF_GATECLOSED, &fsm->t_flag)) {
		dev_err(mdev->dev, "Failed to submit evt, fsm has been removed!\n");
		return FSM_EVT_RET_FAIL;
	}

	event = kzalloc(sizeof(*event),
			(in_hardirq() || in_softirq() || irqs_disabled()) ?
			GFP_ATOMIC : GFP_KERNEL);
	if (!event)
		return FSM_EVT_RET_FAIL;

	kref_init(&event->kref);
	event->mdev = mdev;
	event->id = id;
	event->fsm_flag = flag;
	event->status = FSM_EVT_RET_ONGOING;
	event->data = data;
	event->len = len;
	event->mode = mode;

	spin_lock_irqsave(&fsm->evtq_lock, flags);
	if (test_bit(EVT_TF_GATECLOSED, &fsm->t_flag)) {
		spin_unlock_irqrestore(&fsm->evtq_lock, flags);
		mtk_fsm_evt_put(event);
		dev_err(mdev->dev, "Failed to add event, fsm dev has been removed!\n");
		return FSM_EVT_RET_FAIL;
	}

	kref_get(&event->kref);
	if (mode & EVT_MODE_TOHEAD)
		list_add(&event->entry, &fsm->evtq);
	else
		list_add_tail(&event->entry, &fsm->evtq);
	if (fsm->fsm_handler)
		wake_up_process(fsm->fsm_handler);
	spin_unlock_irqrestore(&fsm->evtq_lock, flags);

	if (mode & EVT_MODE_BLOCKING) {
		ret = wait_event_timeout(fsm->evt_waitq,
					 (event->status != 0), BLOCKING_EVT_TIMEOUT);
		if (!ret && event->status != FSM_EVT_RET_DONE) {
			dev_err(mdev->dev, "Handling fsm blocking event timeout!\n");
			ret = -ETIMEDOUT;
		} else {
			ret = event->status;
		}
	}
	mtk_fsm_evt_put(event);

	return ret;
}
EXPORT_SYMBOL_GPL(mtk_fsm_evt_submit);

static int mtk_fsm_evt_handler(void *__fsm)
{
	struct mtk_md_fsm *fsm = __fsm;
	struct mtk_fsm_evt *event;
	unsigned long flags;
	int ret;

wake_up:
	set_current_state(TASK_INTERRUPTIBLE);
	while (!kthread_should_stop() && !list_empty(&fsm->evtq)) {
		set_current_state(TASK_RUNNING);
		spin_lock_irqsave(&fsm->evtq_lock, flags);
		event = list_first_entry(&fsm->evtq, struct mtk_fsm_evt, entry);
		list_del(&event->entry);
		spin_unlock_irqrestore(&fsm->evtq_lock, flags);

		if (event->id < FSM_EVT_MAX) {
			ret = evts_act_tbl[event->id](fsm, event);
			if (ret) {
				dev_err((fsm->mdev)->dev,
					"Failed to handle evt, fsm state = %d, ret = %d\n",
					fsm->state, ret);
				mtk_fsm_evt_finish(fsm, event, FSM_EVT_RET_FAIL);
			} else {
				mtk_fsm_evt_finish(fsm, event, FSM_EVT_RET_DONE);
			}
		} else {
			mtk_fsm_evt_finish(fsm, event, FSM_EVT_RET_DONE);
		}
	}

	if (kthread_should_stop()) {
		set_current_state(TASK_RUNNING);
		return 0;
	}

	schedule();
	goto wake_up;
}

int mtk_fsm_init(struct mtk_md_dev *mdev)
{
	struct mtk_md_fsm *fsm;
	int ret;

	fsm = devm_kzalloc(mdev->dev, sizeof(*fsm), GFP_KERNEL);
	if (!fsm)
		return -ENOMEM;

	fsm->fsm_handler = kthread_create(mtk_fsm_evt_handler, fsm, "fsm_evt_thread%d_%s",
					  mdev->hw_ver, mdev->dev_str);
	if (IS_ERR(fsm->fsm_handler))
		return PTR_ERR(fsm->fsm_handler);

	/* Keep our own reference so that kthread_stop() in the teardown
	 * paths stays safe even if the thread has already exited (e.g.
	 * it was killed by an oops in a listener it called): without it
	 * the task_struct may be freed and kthread_stop() would hit a
	 * use-after-free through its internal get_task_struct().
	 */
	get_task_struct(fsm->fsm_handler);

	fsm->mdev = mdev;
	fsm->state = FSM_STATE_INVALID;
	fsm->fsm_flag = FSM_F_DFLT;

	INIT_LIST_HEAD(&fsm->evtq);
	spin_lock_init(&fsm->evtq_lock);
	init_waitqueue_head(&fsm->evt_waitq);

	INIT_LIST_HEAD(&fsm->pre_notifiers);
	INIT_LIST_HEAD(&fsm->post_notifiers);
	mutex_init(&fsm->notifier_lock);

	ret = mtk_dev_register_dev_evt(mdev, DEV_EVT_D2H_BOOT_FLOW_SYNC,
				       mtk_fsm_early_bootup_handler, fsm);
	if (ret)
		goto err_stop_thread;

	ret = mtk_fsm_hs_info_init(fsm);
	if (ret)
		goto err_unregister_evt;

	mdev->fsm = fsm;
	return 0;

err_unregister_evt:
	mtk_dev_unregister_dev_evt(mdev, DEV_EVT_D2H_BOOT_FLOW_SYNC);
err_stop_thread:
	/* mdev->fsm is never published on failure, so mtk_fsm_exit() cannot
	 * stop the parked kthread for us; it must be stopped here.
	 */
	kthread_stop(fsm->fsm_handler);
	put_task_struct(fsm->fsm_handler);
	return ret;
}
EXPORT_SYMBOL_GPL(mtk_fsm_init);

/* Close the event gate and join the handler thread, then release the
 * control ports while the port table they reference is still alive.
 * Called from the removal path before the transport plane is dismantled;
 * every step is idempotent, so mtk_fsm_exit() may repeat them safely.
 */
int mtk_fsm_stop(struct mtk_md_dev *mdev)
{
	struct mtk_md_fsm *fsm = mdev->fsm;
	struct task_struct *handler;
	unsigned long flags;

	if (!fsm)
		return -EINVAL;

	spin_lock_irqsave(&fsm->evtq_lock, flags);
	set_bit(EVT_TF_GATECLOSED, &fsm->t_flag);
	handler = fsm->fsm_handler;
	fsm->fsm_handler = NULL;
	spin_unlock_irqrestore(&fsm->evtq_lock, flags);

	if (handler) {
		kthread_stop(handler);
		put_task_struct(handler);
	}

	spin_lock_irqsave(&fsm->evtq_lock, flags);
	mtk_fsm_evt_cleanup(fsm, &fsm->evtq);
	spin_unlock_irqrestore(&fsm->evtq_lock, flags);

	mtk_fsm_ctrl_ch_stop(fsm);

	return 0;
}
EXPORT_SYMBOL_GPL(mtk_fsm_stop);

int mtk_fsm_exit(struct mtk_md_dev *mdev)
{
	struct mtk_md_fsm *fsm = mdev->fsm;
	struct task_struct *handler;
	unsigned long flags;

	if (!fsm)
		return -EINVAL;

	spin_lock_irqsave(&fsm->evtq_lock, flags);
	set_bit(EVT_TF_GATECLOSED, &fsm->t_flag);
	handler = fsm->fsm_handler;
	fsm->fsm_handler = NULL;
	spin_unlock_irqrestore(&fsm->evtq_lock, flags);

	if (handler) {
		kthread_stop(handler);
		put_task_struct(handler);
	}

	spin_lock_irqsave(&fsm->evtq_lock, flags);
	if (WARN_ON(!list_empty(&fsm->evtq)))
		mtk_fsm_evt_cleanup(fsm, &fsm->evtq);
	spin_unlock_irqrestore(&fsm->evtq_lock, flags);

	/* Release the port references and recv callbacks even when the
	 * DEV_RM event never ran (its enter-off path is the only other
	 * caller); mtk_fsm_ctrl_ch_stop() is idempotent.
	 */
	mtk_fsm_ctrl_ch_stop(fsm);

	for (int i = 0; i < HS_ID_MAX; i++) {
		if (fsm->hs_info[i].rt_data) {
			dev_kfree_skb(fsm->hs_info[i].rt_data);
			fsm->hs_info[i].rt_data = NULL;
		}
	}

	mutex_lock(&fsm->notifier_lock);
	mkt_fsm_notifier_cleanup(mdev, &fsm->pre_notifiers);
	mkt_fsm_notifier_cleanup(mdev, &fsm->post_notifiers);
	mutex_unlock(&fsm->notifier_lock);

	mtk_dev_unregister_dev_evt(mdev, DEV_EVT_D2H_BOOT_FLOW_SYNC);
	mtk_fsm_hs_info_exit(fsm);
	mdev->fsm = NULL;

	return 0;
}
EXPORT_SYMBOL_GPL(mtk_fsm_exit);
