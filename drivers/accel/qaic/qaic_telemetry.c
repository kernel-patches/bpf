// SPDX-License-Identifier: GPL-2.0-only

/* Copyright (c) 2020-2021, The Linux Foundation. All rights reserved. */
/* Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries. */

#include <asm/byteorder.h>
#include <drm/drm_file.h>
#include <drm/drm_ras.h>
#include <linux/completion.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/kernel.h>
#include <linux/kref.h>
#include <linux/limits.h>
#include <linux/list.h>
#include <linux/mhi.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/sprintf.h>
#include <linux/srcu.h>
#include <linux/types.h>
#include <linux/workqueue.h>
#include <uapi/drm/qaic_accel.h>

#include "qaic.h"
#include "qaic_telemetry.h"

#define MAGIC				0x55AA
#define VERSION				0x1

/*
 * Telemetry fields defined by the uAPI.
 * This table will be used by drm_ras's dumpit to display
 * each field to userspace.
 */
#define QAIC_FIELD_RO(_name) \
	{#_name, _name, DRM_RAS_TELEMETRY_FIELD_MODE_READ}
#define QAIC_FIELD_RW(_name) \
	{#_name, _name, DRM_RAS_TELEMETRY_FIELD_MODE_READ | DRM_RAS_TELEMETRY_FIELD_MODE_WRITE}

static const struct drm_ras_telemetry_field qaic_telemetry_fields[] = {
	QAIC_FIELD_RO(QAIC_DEVINFO_THERMAL_SOC_MAX_TEMP),
	QAIC_FIELD_RO(QAIC_DEVINFO_THERMAL_BOARD_TEMP),
	QAIC_FIELD_RO(QAIC_DEVINFO_THERMAL_BOARD_MAX_TEMP),
	QAIC_FIELD_RO(QAIC_DEVINFO_THERMAL_DDR_TEMP),
	QAIC_FIELD_RW(QAIC_DEVINFO_THERMAL_WARNING_TEMP),
	QAIC_FIELD_RW(QAIC_DEVINFO_THERMAL_SHUTDOWN_TEMP),
	QAIC_FIELD_RW(QAIC_DEVINFO_BOARD_TDP),
	QAIC_FIELD_RO(QAIC_DEVINFO_BOARD_POWER),
	QAIC_FIELD_RW(QAIC_DEVINFO_POWER_STATE),
	QAIC_FIELD_RO(QAIC_DEVINFO_POWER_MAX),
	QAIC_FIELD_RO(QAIC_DEVINFO_THROTTLE_PERCENT),
	QAIC_FIELD_RO(QAIC_DEVINFO_THROTTLE_TIME),
	QAIC_FIELD_RO(QAIC_DEVINFO_UPTIME),
	QAIC_FIELD_RO(QAIC_DEVINFO_THERMAL_SOC_FLOOR_TEMP),
	QAIC_FIELD_RO(QAIC_DEVINFO_THERMAL_SOC_CEILING_TEMP),
	QAIC_FIELD_RO(QAIC_DEVINFO_VOLTAGE_CX),
	QAIC_FIELD_RO(QAIC_DEVINFO_VOLTAGE_MX),
	QAIC_FIELD_RO(QAIC_DEVINFO_VOLTAGE_NSP_CX),
	QAIC_FIELD_RO(QAIC_DEVINFO_VOLTAGE_NSP_MX),
	QAIC_FIELD_RW(QAIC_DEVINFO_CFG_TOPS),
	QAIC_FIELD_RO(QAIC_DEVINFO_THERMAL_PMIC_TEMP_A),
	QAIC_FIELD_RO(QAIC_DEVINFO_THERMAL_PMIC_TEMP_C),
	QAIC_FIELD_RO(QAIC_DEVINFO_THERMAL_PMIC_TEMP_E),
	QAIC_FIELD_RW(QAIC_DEVINFO_POWER_ACTION),
	QAIC_FIELD_RW(QAIC_DEVINFO_SOC_TDP),
	QAIC_FIELD_RO(QAIC_DEVINFO_SOC_POWER),
	{},
};

#undef QAIC_FIELD_RO
#undef QAIC_FIELD_RW

enum fw_errno {
	ERR_READ_ONLY		= -1,
	ERR_NOT_SUPPORTED	= -2,
	ERR_WHILE_PROCESSING	= -3,
	ERR_INVALID_VALUE	= -4,
	ERR_INVALID_HEADER	= -5,
};

enum cmd_type {
	TYPE_READ,  /* read value from device */
	TYPE_WRITE, /* write value to device */
};

enum msg_type {
	MSG_PUSH, /* async push from device */
	MSG_REQ,  /* sync request to device */
	MSG_RESP, /* sync response from device */
};

struct telemetry_data {
	u8	cmd;
	u8	cmd_type;
	u8	status;
	__le64	val; /* signed */
} __packed;

struct telemetry_header {
	__le16	magic;
	__le16	ver;
	__le32	seq_num;
	u8	type;
	u8	id;
	__le16	len;
} __packed;

struct telemetry_msg { /* little endian encoded */
	struct telemetry_header hdr;
	struct telemetry_data data;
} __packed;

struct wrapper_msg {
	struct kref ref_count;
	struct telemetry_msg msg;
};

struct xfer_queue_elem {
	/*
	 * Node in list of ongoing transfer request on telemetry channel.
	 * Maintained by root device struct
	 */
	struct list_head list;
	/* Sequence number of this transfer request */
	u32 seq_num;
	/* This is used to wait on until completion of transfer request */
	struct completion xfer_done;
	/* Received data from device */
	void *buf;
};

struct resp_work {
	/* Work struct to schedule work coming on QAIC_TELEMETRY channel */
	struct work_struct work;
	/* Root struct of device, used to access device resources */
	struct qaic_device *qdev;
	/* Buffer used by MHI for transfer requests */
	void *buf;
};

static void free_wrapper(struct kref *ref)
{
	struct wrapper_msg *wrapper = container_of(ref, struct wrapper_msg, ref_count);

	kfree(wrapper);
}

static int telemetry_request(struct qaic_device *qdev, u8 cmd, u8 cmd_type, s64 *val, s64 *status)
{
	struct wrapper_msg *wrapper;
	struct xfer_queue_elem elem;
	struct telemetry_msg *resp;
	struct telemetry_msg *req;
	long ret = 0;

	wrapper = kzalloc_obj(*wrapper);
	if (!wrapper)
		return -ENOMEM;

	kref_init(&wrapper->ref_count);
	req = &wrapper->msg;

	ret = mutex_lock_interruptible(&qdev->tele_mutex);
	if (ret)
		goto free_req;

	if (!qdev->tele_ch || qdev->dev_state != QAIC_ONLINE) {
		mutex_unlock(&qdev->tele_mutex);
		ret = -ENODEV;
		goto free_req;
	}

	req->hdr.magic = cpu_to_le16(MAGIC);
	req->hdr.ver = cpu_to_le16(VERSION);
	req->hdr.seq_num = cpu_to_le32(qdev->tele_next_seq_num++);
	req->hdr.type = MSG_REQ;
	req->hdr.id = 0;
	req->hdr.len = cpu_to_le16(sizeof(req->data));

	req->data.cmd = cmd;
	req->data.cmd_type = cmd_type;
	req->data.status = 0;
	if (cmd_type == TYPE_READ)
		req->data.val = cpu_to_le64(0);
	else
		req->data.val = cpu_to_le64(*val);

	elem.seq_num = qdev->tele_next_seq_num - 1;
	elem.buf = NULL;
	init_completion(&elem.xfer_done);
	if (likely(!qdev->tele_lost_buf)) {
		resp = kzalloc_obj(*resp);
		if (!resp) {
			mutex_unlock(&qdev->tele_mutex);
			ret = -ENOMEM;
			goto free_req;
		}

		ret = mhi_queue_buf(qdev->tele_ch, DMA_FROM_DEVICE, resp, sizeof(*resp), MHI_EOT);
		if (ret) {
			mutex_unlock(&qdev->tele_mutex);
			goto free_resp;
		}
	} else {
		/*
		 * we lost a buffer because we queued a recv buf, but then
		 * queuing the corresponding tx buf failed. To try to avoid
		 * a memory leak, lets reclaim it and use it for this
		 * transaction.
		 */
		qdev->tele_lost_buf = false;
	}

	kref_get(&wrapper->ref_count);
	ret = mhi_queue_buf(qdev->tele_ch, DMA_TO_DEVICE, req, sizeof(*req), MHI_EOT);
	if (ret) {
		qdev->tele_lost_buf = true;
		kref_put(&wrapper->ref_count, free_wrapper);
		mutex_unlock(&qdev->tele_mutex);
		goto free_req;
	}

	list_add_tail(&elem.list, &qdev->tele_xfer_list);
	mutex_unlock(&qdev->tele_mutex);

	ret = wait_for_completion_interruptible_timeout(&elem.xfer_done, HZ);
	/*
	 * not using _interruptable because we have to cleanup or we'll
	 * likely cause memory corruption
	 */
	mutex_lock(&qdev->tele_mutex);
	if (!list_empty(&elem.list))
		list_del(&elem.list);
	/* resp_worker() processed the response but the wait was interrupted */
	else if (ret == -ERESTARTSYS)
		ret = 0;
	if (!ret && !elem.buf)
		ret = -ETIMEDOUT;
	else if (ret > 0 && !elem.buf)
		ret = -EIO;
	mutex_unlock(&qdev->tele_mutex);

	resp = elem.buf;

	/*
	 * telemetry_request() is called from Generic Netlink .doit callbacks
	 * rather than a syscall boundary, so -ERESTARTSYS is never translated
	 * to -EINTR before it would otherwise be serialized as-is into the
	 * netlink error ack.
	 */
	if (ret == -ERESTARTSYS)
		ret = -EINTR;

	if (ret < 0)
		goto free_resp;

	if (le16_to_cpu(resp->hdr.magic) != MAGIC || le16_to_cpu(resp->hdr.ver) != VERSION ||
	    resp->hdr.type != MSG_RESP || resp->hdr.id != 0 ||
	    le16_to_cpu(resp->hdr.len) != sizeof(resp->data) || resp->data.cmd != cmd ||
	    resp->data.cmd_type != cmd_type) {
		ret = -EINVAL;
		goto free_resp;
	}

	if (resp->data.status) {
		switch ((s8)resp->data.status) {
		case ERR_READ_ONLY:
			*status = -EROFS;
			break;
		case ERR_NOT_SUPPORTED:
			*status = -EOPNOTSUPP;
			break;
		case ERR_WHILE_PROCESSING:
			*status = -EREMOTEIO;
			break;
		case ERR_INVALID_VALUE:
			*status = -EINVAL;
			break;
		case ERR_INVALID_HEADER:
			*status = -EBADR;
			break;
		default:
			*status = -EPROTO;
		}
		ret = 0;
		goto free_resp;
	}

	if (cmd_type == TYPE_READ)
		*val = le64_to_cpu(resp->data.val);

	ret = 0;

free_resp:
	kfree(resp);
free_req:
	kref_put(&wrapper->ref_count, free_wrapper);

	return ret;
}

static void resp_worker(struct work_struct *work)
{
	struct resp_work *resp = container_of(work, struct resp_work, work);
	struct qaic_device *qdev = resp->qdev;
	struct telemetry_msg *msg = resp->buf;
	struct xfer_queue_elem *elem;
	struct xfer_queue_elem *i;
	bool found = false;

	if (le16_to_cpu(msg->hdr.magic) != MAGIC) {
		kfree(msg);
		kfree(resp);
		return;
	}

	mutex_lock(&qdev->tele_mutex);
	list_for_each_entry_safe(elem, i, &qdev->tele_xfer_list, list) {
		if (elem->seq_num == le32_to_cpu(msg->hdr.seq_num)) {
			found = true;
			list_del_init(&elem->list);
			elem->buf = msg;
			complete_all(&elem->xfer_done);
			break;
		}
	}
	mutex_unlock(&qdev->tele_mutex);

	if (!found)
		/* request must have timed out, drop packet */
		kfree(msg);

	kfree(resp);
}

static void qaic_telemetry_mhi_ul_xfer_cb(struct mhi_device *mhi_dev,
					  struct mhi_result *mhi_result)
{
	struct telemetry_msg *msg = mhi_result->buf_addr;
	struct wrapper_msg *wrapper;

	wrapper = container_of(msg, struct wrapper_msg, msg);
	kref_put(&wrapper->ref_count, free_wrapper);
}

static void qaic_telemetry_mhi_dl_xfer_cb(struct mhi_device *mhi_dev,
					  struct mhi_result *mhi_result)
{
	struct qaic_device *qdev = dev_get_drvdata(&mhi_dev->dev);
	struct telemetry_msg *msg = mhi_result->buf_addr;
	struct resp_work *resp;

	if (mhi_result->transaction_status) {
		kfree(msg);
		return;
	}

	resp = kmalloc(sizeof(*resp), GFP_ATOMIC);
	if (!resp) {
		pci_err(qdev->pdev, "dl_xfer_cb alloc fail, dropping message\n");
		kfree(msg);
		return;
	}

	INIT_WORK(&resp->work, resp_worker);
	resp->qdev = qdev;
	resp->buf = msg;
	queue_work(qdev->tele_wq, &resp->work);
}

static int qaic_telemetry_pre(struct drm_ras_node *ep)
{
	struct qaic_device *qdev = ep->priv;
	struct inode *dev_inode;
	struct path path;
	char devpath[24];
	int ret;

	snprintf(devpath, sizeof(devpath), "/dev/accel/%s", to_accel_kdev(qdev->qddev)->kobj.name);
	scoped_with_init_fs()
		ret = kern_path(devpath, LOOKUP_FOLLOW, &path);
	if (ret)
		return -EINVAL;

	dev_inode = d_inode(path.dentry);
	ret = inode_permission(&nop_mnt_idmap, dev_inode, MAY_READ | MAY_WRITE);
	path_put(&path);

	return ret;
}

static int qaic_telemetry_get(struct drm_ras_node *ep, u64 *field, s64 *value, s64 *status)
{
	struct qaic_device *qdev = ep->priv;
	int rcu_id;
	int ret;

	/* telemetry_request expects the field to be a u8 */
	if (*field > U8_MAX)
		return -EINVAL;

	rcu_id = srcu_read_lock(&qdev->dev_lock);
	if (qdev->dev_state != QAIC_ONLINE) {
		srcu_read_unlock(&qdev->dev_lock, rcu_id);
		return -ENODEV;
	}

	ret = telemetry_request(qdev, (u8)*field, TYPE_READ, value, status);
	srcu_read_unlock(&qdev->dev_lock, rcu_id);

	return ret;
}

static int qaic_telemetry_set(struct drm_ras_node *ep, u64 *field, s64 *value, s64 *status)
{
	struct qaic_device *qdev = ep->priv;
	int rcu_id;
	int ret;

	/* telemetry_request expects the field to be a u8 */
	if (*field > U8_MAX)
		return -EINVAL;

	rcu_id = srcu_read_lock(&qdev->dev_lock);
	if (qdev->dev_state != QAIC_ONLINE) {
		srcu_read_unlock(&qdev->dev_lock, rcu_id);
		return -ENODEV;
	}

	ret = telemetry_request(qdev, (u8)*field, TYPE_WRITE, value, status);
	srcu_read_unlock(&qdev->dev_lock, rcu_id);

	return ret;
}

static int qaic_drm_ras_register_node(struct qaic_device *qdev)
{
	struct drm_ras_node *node;
	struct pci_dev *pdev = qdev->pdev;
	const char *device_name, *node_name;
	int ret;

	node = kzalloc_obj(struct drm_ras_node);
	if (!node)
		return -ENOMEM;

	device_name = kasprintf(GFP_KERNEL, "%04x:%02x:%02x.%d",
				pci_domain_nr(pdev->bus), pdev->bus->number,
				PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn));
	if (!device_name) {
		kfree(node);
		return -ENOMEM;
	}

	node_name = kasprintf(GFP_KERNEL, "qaic_telemetry");
	if (!node_name) {
		kfree(device_name);
		kfree(node);
		return -ENOMEM;
	}

	node->device_name = device_name;
	node->node_name = node_name;
	node->type = DRM_RAS_NODE_TYPE_TELEMETRY;
	node->priv = qdev;
	node->telemetry_get = qaic_telemetry_get;
	node->telemetry_set = qaic_telemetry_set;
	node->telemetry_pre = qaic_telemetry_pre;
	node->telemetry_fields = qaic_telemetry_fields;

	ret = drm_ras_node_register(node);
	if (ret) {
		kfree(device_name);
		kfree(node_name);
		kfree(node);
		return ret;
	}

	qdev->ras_node = node;
	return 0;
}

static void qaic_drm_ras_unregister_node(struct qaic_device *qdev)
{
	drm_ras_node_unregister(qdev->ras_node);
	kfree(qdev->ras_node->node_name);
	kfree(qdev->ras_node->device_name);
	kfree(qdev->ras_node);
}

static int qaic_telemetry_mhi_probe(struct mhi_device *mhi_dev, const struct mhi_device_id *id)
{
	struct qaic_device *qdev = pci_get_drvdata(to_pci_dev(mhi_dev->mhi_cntrl->cntrl_dev));
	int ret;

	ret = mhi_prepare_for_transfer(mhi_dev);
	if (ret)
		return ret;

	dev_set_drvdata(&mhi_dev->dev, qdev);
	qdev->tele_ch = mhi_dev;
	qdev->tele_lost_buf = false;

	ret = qaic_drm_ras_register_node(qdev);
	if (ret) {
		mhi_unprepare_from_transfer(mhi_dev);
		qdev->tele_ch = NULL;
		return ret;
	}

	return 0;
}

static void qaic_telemetry_mhi_remove(struct mhi_device *mhi_dev)
{
	struct qaic_device *qdev = dev_get_drvdata(&mhi_dev->dev);

	qaic_drm_ras_unregister_node(qdev);
	mhi_unprepare_from_transfer(qdev->tele_ch);
	flush_workqueue(qdev->tele_wq);
	qdev->tele_ch = NULL;
}

static const struct mhi_device_id qaic_telemetry_mhi_match_table[] = {
	{ .chan = "QAIC_TELEMETRY", },
	{},
};

static struct mhi_driver qaic_telemetry_mhi_driver = {
	.id_table = qaic_telemetry_mhi_match_table,
	.remove = qaic_telemetry_mhi_remove,
	.probe = qaic_telemetry_mhi_probe,
	.ul_xfer_cb = qaic_telemetry_mhi_ul_xfer_cb,
	.dl_xfer_cb = qaic_telemetry_mhi_dl_xfer_cb,
	.driver = {
		.name = "qaic_telemetry",
	},
};

int qaic_telemetry_register(void)
{
	return mhi_driver_register(&qaic_telemetry_mhi_driver);
}

void qaic_telemetry_unregister(void)
{
	mhi_driver_unregister(&qaic_telemetry_mhi_driver);
}

void wake_all_telemetry(struct qaic_device *qdev)
{
	struct xfer_queue_elem *elem;
	struct xfer_queue_elem *i;

	mutex_lock(&qdev->tele_mutex);
	list_for_each_entry_safe(elem, i, &qdev->tele_xfer_list, list) {
		list_del_init(&elem->list);
		complete_all(&elem->xfer_done);
	}
	qdev->tele_lost_buf = false;
	mutex_unlock(&qdev->tele_mutex);
}
