// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Nebula Matrix Limited.
 */
#include <linux/device.h>
#include <linux/pci.h>
#include "nbl_dev.h"

static void nbl_dev_clean_mailbox_schedule(struct nbl_dev_mgt *dev_mgt);

/* ----------  Interrupt config  ---------- */
static irqreturn_t nbl_dev_clean_mailbox(int irq __always_unused, void *data)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)data;

	nbl_dev_clean_mailbox_schedule(dev_mgt);
	return IRQ_HANDLED;
}

static void nbl_dev_init_msix_cnt(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_dev_common *dev_common = dev_mgt->common_dev;
	struct nbl_msix_info *msix_info = &dev_common->msix_info;

	/* mailbox vector allocated in nbl_dev_start() via
	 * nbl_dev_init_interrupt_scheme(); nbl_dev_request_mailbox_irq()
	 * only attaches the irq handler to pre-allocated vectors.
	 */
	msix_info->serv_info[NBL_MSIX_MAILBOX_TYPE].num = 1;
}

static int nbl_dev_request_mailbox_irq(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_dev_common *dev_common = dev_mgt->common_dev;
	struct nbl_msix_info *msix_info = &dev_common->msix_info;
	struct nbl_common_info *common = dev_mgt->common;
	u16 lvec;
	int irq_num;
	int err;

	if (!msix_info->serv_info[NBL_MSIX_MAILBOX_TYPE].num)
		return 0;

	lvec = msix_info->serv_info[NBL_MSIX_MAILBOX_TYPE].base_vector_id;
	irq_num = pci_irq_vector(common->pdev, lvec);
	if (irq_num < 0) {
		dev_err(common->dev, "Failed to get mailbox IRQ vector: %d\n",
			irq_num);
		return irq_num;
	}

	snprintf(dev_common->mailbox_name, sizeof(dev_common->mailbox_name),
		 "nbl_mailbox@pci:%s", pci_name(common->pdev));
	err = request_irq(irq_num, nbl_dev_clean_mailbox, 0,
			  dev_common->mailbox_name, dev_mgt);
	if (err)
		return err;

	return 0;
}

static void nbl_dev_free_mailbox_irq(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_dev_common *dev_common = dev_mgt->common_dev;
	struct nbl_msix_info *msix_info = &dev_common->msix_info;
	struct nbl_common_info *common = dev_mgt->common;
	u16 lvec;
	int irq_num;

	if (!msix_info->serv_info[NBL_MSIX_MAILBOX_TYPE].num)
		return;

	lvec = msix_info->serv_info[NBL_MSIX_MAILBOX_TYPE].base_vector_id;
	irq_num = pci_irq_vector(common->pdev, lvec);
	if (irq_num >= 0)
		free_irq(irq_num, dev_mgt);
}

static int nbl_dev_enable_mailbox_irq(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_dispatch_ops *disp_ops = dev_mgt->disp_ops_tbl->ops;
	struct nbl_channel_ops *chan_ops = dev_mgt->chan_ops_tbl->ops;
	struct nbl_dev_common *dev_common = dev_mgt->common_dev;
	struct nbl_msix_info *msix_info = &dev_common->msix_info;
	u16 lvec;
	int ret;

	if (!msix_info->serv_info[NBL_MSIX_MAILBOX_TYPE].num)
		return 0;

	lvec = msix_info->serv_info[NBL_MSIX_MAILBOX_TYPE].base_vector_id;
	/*
	 * Enable sequence: perform set_mailbox_irq RPC in polling mode first.
	 * Only set NBL_CHAN_IRQ_RDY after RPC succeeds, mirroring disable path.
	 * This avoids waiting for an interrupt which has not been armed yet.
	 */
	ret = disp_ops->set_mailbox_irq(dev_mgt->disp_ops_tbl->priv,
					lvec, true);
	if (ret)
		return ret;
	chan_ops->set_queue_state(dev_mgt->chan_ops_tbl->priv,
				  NBL_CHAN_IRQ_RDY,
				  NBL_CHAN_TYPE_MAILBOX, true);
	return 0;
}

static int nbl_dev_disable_mailbox_irq(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_dispatch_ops *disp_ops = dev_mgt->disp_ops_tbl->ops;
	struct nbl_channel_ops *chan_ops = dev_mgt->chan_ops_tbl->ops;
	struct nbl_dev_common *dev_common = dev_mgt->common_dev;
	struct nbl_msix_info *msix_info = &dev_common->msix_info;
	u16 lvec;

	if (!msix_info->serv_info[NBL_MSIX_MAILBOX_TYPE].num)
		return 0;

	lvec = msix_info->serv_info[NBL_MSIX_MAILBOX_TYPE].base_vector_id;
	/*
	 * Disable sequence invariant: update software state first, then mask
	 * hardware interrupt. Must not reverse the order.
	 *
	 * If hardware interrupt is masked before clearing INTERRUPT_READY,
	 * the hardware may still transmit outstanding ACK packets for in-flight
	 * messages. Subsequent switch to polling mode discards pending ACK
	 * processing, triggering "Channel waiting ack failed" and "Skip ack
	 * with invalid status" errors.
	 *
	 * By entering polling mode first, any late hardware interrupts are
	 * ignored without pending ACK expectations, then hardware interrupt
	 * can be safely disabled.
	 *
	 * This helper is invoked in two paths:
	 * 1. Error unwind path of nbl_dev_start(): followed immediately by
	 * nbl_dev_free_mailbox_irq() and full channel teardown. No new mailbox
	 * interrupts can fire afterwards, and subsequent cancel_work_sync()
	 * drains pending cleanup work before resources are released.
	 * 2. Normal device stop path nbl_dev_stop(): free_irq() blocks until
	 * any in-flight hardirq handler completes and prevents new interrupts.
	 * cancel_work_sync() then waits for any already running mailbox cleanup
	 * work to finish, or cancels queued but unstarted work items before
	 * final channel destruction. No stuck descriptors linger in either
	 * scenario.
	 */
	chan_ops->set_queue_state(dev_mgt->chan_ops_tbl->priv,
				  NBL_CHAN_IRQ_RDY,
				  NBL_CHAN_TYPE_MAILBOX, false);

	return disp_ops->set_mailbox_irq(dev_mgt->disp_ops_tbl->priv,
					 lvec, false);
}

static int nbl_dev_cfg_msix_map(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_dispatch_ops *disp_ops = dev_mgt->disp_ops_tbl->ops;
	struct nbl_dev_common *dev_common = dev_mgt->common_dev;
	struct nbl_msix_info *msix_info = &dev_common->msix_info;
	bool mask_en = msix_info->serv_info[NBL_MSIX_NET_TYPE].hw_self_mask_en;
	u16 msix_net_num = msix_info->serv_info[NBL_MSIX_NET_TYPE].num;
	u16 msix_not_net_num = 0;
	int err, i;

	msix_info->serv_info[NBL_MSIX_NET_TYPE].base_vector_id = 0;
	/*
	 * Calculate base_vector_id for each MSIX service type.
	 * This relies on NBL_MSIX_TYPE enum being ordered sequentially,
	 * starting from NBL_MSIX_NET_TYPE.
	 */
	for (i = NBL_MSIX_NET_TYPE + 1; i < NBL_MSIX_TYPE_MAX; i++)
		msix_info->serv_info[i].base_vector_id =
			msix_info->serv_info[i - 1].base_vector_id +
			msix_info->serv_info[i - 1].num;

	for (i = 0; i < NBL_MSIX_TYPE_MAX; i++) {
		if (i == NBL_MSIX_NET_TYPE)
			continue;
		msix_not_net_num += msix_info->serv_info[i].num;
	}

	err = disp_ops->cfg_msix_map(dev_mgt->disp_ops_tbl->priv,
				     msix_net_num, msix_not_net_num,
				     mask_en);

	return err;
}

static int nbl_dev_destroy_msix_map(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_dispatch_ops *disp_ops = dev_mgt->disp_ops_tbl->ops;

	return disp_ops->destroy_msix_map(dev_mgt->disp_ops_tbl->priv);
}

static int nbl_dev_init_interrupt_scheme(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_dev_common *dev_common = dev_mgt->common_dev;
	struct nbl_msix_info *msix_info = &dev_common->msix_info;
	struct nbl_common_info *common = dev_mgt->common;
	int needed = 0;
	int err;
	int i;

	for (i = 0; i < NBL_MSIX_TYPE_MAX; i++)
		needed += msix_info->serv_info[i].num;

	err = pci_alloc_irq_vectors(common->pdev, needed, needed,
				    PCI_IRQ_MSIX | PCI_IRQ_AFFINITY);
	if (err < 0) {
		dev_err(common->dev,
			"pci_alloc_irq_vectors failed, err = %d\n", err);
		return err;
	}
	if (err != needed) {
		dev_err(common->dev, "pci_alloc_irq_vectors got %d vecs, need %d\n",
			err, needed);
		return -ENOSPC;
	}
	return 0;
}

static void nbl_dev_clear_interrupt_scheme(struct nbl_dev_mgt *dev_mgt)
{
	/*
	 * pcim_enable_device() is used in nbl_probe().
	 * pci_alloc_irq_vectors() registers pcim_msi_release devres callback,
	 * which invokes pci_free_irq_vectors() automatically on device detach.
	 * Do NOT call pci_free_irq_vectors() explicitly here to avoid
	 * double-free.
	 */
}

/* ----------  Channel config  ---------- */
static void nbl_dev_setup_chan_qinfo(struct nbl_dev_mgt *dev_mgt, u8 chan_type)
{
	struct nbl_channel_ops *chan_ops = dev_mgt->chan_ops_tbl->ops;
	struct nbl_channel_mgt *priv = dev_mgt->chan_ops_tbl->priv;
	struct nbl_common_info *common = dev_mgt->common;

	if (!chan_ops->check_queue_exist(priv, chan_type))
		return;

	chan_ops->cfg_chan_qinfo_map_table(priv, common->hw_bus, common->devid);
}

static int nbl_dev_setup_chan_queue(struct nbl_dev_mgt *dev_mgt, u8 chan_type)
{
	struct nbl_channel_ops *chan_ops = dev_mgt->chan_ops_tbl->ops;
	struct nbl_channel_mgt *priv = dev_mgt->chan_ops_tbl->priv;
	int ret = 0;

	if (chan_ops->check_queue_exist(priv, chan_type))
		ret = chan_ops->setup_queue(priv, chan_type);

	return ret;
}

static int nbl_dev_remove_chan_queue(struct nbl_dev_mgt *dev_mgt, u8 chan_type)
{
	struct nbl_channel_ops *chan_ops = dev_mgt->chan_ops_tbl->ops;
	struct nbl_channel_mgt *priv = dev_mgt->chan_ops_tbl->priv;
	int ret = 0;

	if (chan_ops->check_queue_exist(priv, chan_type))
		ret = chan_ops->teardown_queue(priv, chan_type);

	return ret;
}

static void nbl_dev_register_chan_task(struct nbl_dev_mgt *dev_mgt,
				       u8 chan_type, struct work_struct *task)
{
	struct nbl_channel_ops *chan_ops = dev_mgt->chan_ops_tbl->ops;

	if (chan_ops->check_queue_exist(dev_mgt->chan_ops_tbl->priv, chan_type))
		chan_ops->register_chan_task(dev_mgt->chan_ops_tbl->priv,
					     chan_type, task);
}

/* ----------  Tasks config  ---------- */
static void nbl_dev_clean_mailbox_task(struct work_struct *work)
{
	struct nbl_dev_common *common_dev =
		container_of(work, struct nbl_dev_common, clean_mbx_task);
	struct nbl_dev_mgt *dev_mgt = common_dev->dev_mgt;
	struct nbl_channel_ops *chan_ops = dev_mgt->chan_ops_tbl->ops;

	chan_ops->clean_queue_subtask(dev_mgt->chan_ops_tbl->priv,
				      NBL_CHAN_TYPE_MAILBOX);
}

static void nbl_dev_clean_mailbox_schedule(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_dev_common *common_dev = dev_mgt->common_dev;
	struct nbl_common_info *common = dev_mgt->common;

	queue_work(common->wq, &common_dev->clean_mbx_task);
}

/* ----------  Dev init process  ---------- */
static int nbl_dev_setup_common_dev(struct nbl_adapter *adapter)
{
	struct nbl_dev_mgt *dev_mgt = adapter->core.dev_mgt;
	struct nbl_dev_common *common_dev;
	int ret;

	common_dev = devm_kzalloc(&adapter->pdev->dev, sizeof(*common_dev),
				  GFP_KERNEL);
	if (!common_dev)
		return -ENOMEM;
	common_dev->dev_mgt = dev_mgt;

	ret = nbl_dev_setup_chan_queue(dev_mgt, NBL_CHAN_TYPE_MAILBOX);
	if (ret)
		goto err_cleanup;

	INIT_WORK(&common_dev->clean_mbx_task, nbl_dev_clean_mailbox_task);
	nbl_dev_register_chan_task(dev_mgt, NBL_CHAN_TYPE_MAILBOX,
				   &common_dev->clean_mbx_task);
	/*
	 * VSI/ETH identity fetch moved to nbl_dev_start().
	 * This avoids cross-PF probe race when manager PF is not ready.
	 */
	dev_mgt->common_dev = common_dev;
	nbl_dev_init_msix_cnt(dev_mgt);

	return 0;
err_cleanup:
	cancel_work_sync(&common_dev->clean_mbx_task);
	nbl_dev_remove_chan_queue(dev_mgt, NBL_CHAN_TYPE_MAILBOX);
	nbl_dev_register_chan_task(dev_mgt, NBL_CHAN_TYPE_MAILBOX, NULL);
	return ret;
}

static void nbl_dev_remove_common_dev(struct nbl_adapter *adapter)
{
	struct nbl_dev_mgt *dev_mgt = adapter->core.dev_mgt;
	struct nbl_dev_common *common_dev = dev_mgt->common_dev;

	if (!common_dev)
		return;
	cancel_work_sync(&common_dev->clean_mbx_task);
	nbl_dev_remove_chan_queue(dev_mgt, NBL_CHAN_TYPE_MAILBOX);
	nbl_dev_register_chan_task(dev_mgt, NBL_CHAN_TYPE_MAILBOX, NULL);
}

static int nbl_dev_setup_ctrl_dev(struct nbl_adapter *adapter)
{
	struct nbl_dev_mgt *dev_mgt = adapter->core.dev_mgt;
	struct nbl_dispatch_ops *disp_ops = dev_mgt->disp_ops_tbl->ops;
	int ret;

	ret = disp_ops->init_module(dev_mgt->disp_ops_tbl->priv);
	if (ret)
		return ret;

	nbl_dev_setup_chan_qinfo(dev_mgt, NBL_CHAN_TYPE_MAILBOX);

	return 0;
}

/*
 * Tear down control device: deinit_module sets driver_status=false
 * to notify firmware to clean all per-PF hardware state (including
 * qinfo registers).  The qinfo map programmed in setup_ctrl_dev is
 * not explicitly cleared; firmware handles it on driver_status change.
 *
 * NOTE: Firmware clears chip-global qinfo routing entries when control PF
 * deinit runs.  MUST unbind all sibling non-control PFs on the same chip
 * BEFORE unbinding the control PF. Unbinding control PF while siblings are
 * still bound will leave those sibling PFs with broken mailbox RPC,
 * causing RPC ACK timeouts. This operation sequence is NOT supported.
 */
static void nbl_dev_remove_ctrl_dev(struct nbl_adapter *adapter)
{
	struct nbl_dev_mgt *dev_mgt = adapter->core.dev_mgt;
	struct nbl_dispatch_ops *disp_ops = dev_mgt->disp_ops_tbl->ops;

	disp_ops->deinit_module(dev_mgt->disp_ops_tbl->priv);
}

static struct nbl_dev_mgt *nbl_dev_setup_dev_mgt(struct nbl_common_info *common)
{
	struct nbl_dev_mgt *dev_mgt;

	dev_mgt = devm_kzalloc(common->dev, sizeof(*dev_mgt), GFP_KERNEL);
	if (!dev_mgt)
		return ERR_PTR(-ENOMEM);

	dev_mgt->common = common;
	return dev_mgt;
}

int nbl_dev_init(struct nbl_adapter *adapter)
{
	struct nbl_common_info *common = &adapter->common;
	struct nbl_dispatch_ops_tbl *disp_ops_tbl =
		adapter->intf.dispatch_ops_tbl;
	struct nbl_channel_ops_tbl *chan_ops_tbl =
		adapter->intf.channel_ops_tbl;
	struct nbl_dev_mgt *dev_mgt;
	int ret;

	dev_mgt = nbl_dev_setup_dev_mgt(common);
	if (IS_ERR(dev_mgt)) {
		ret = PTR_ERR(dev_mgt);
		return ret;
	}

	dev_mgt->disp_ops_tbl = disp_ops_tbl;
	dev_mgt->chan_ops_tbl = chan_ops_tbl;
	adapter->core.dev_mgt = dev_mgt;

	/*
	 * Chip hardware initialization is completed by firmware at power-up.
	 * Only driver functional table/register config follows here, safe to
	 * access hardware registers before ctrl dev setup.
	 */
	ret = nbl_dev_setup_common_dev(adapter);
	if (ret)
		goto setup_err;

	if (common->has_ctrl) {
		ret = nbl_dev_setup_ctrl_dev(adapter);
		if (ret)
			goto setup_ctrl_dev_fail;
	}

	return 0;
setup_ctrl_dev_fail:
	nbl_dev_remove_common_dev(adapter);
setup_err:
	return ret;
}

/*
 * Teardown order: Stop mailbox channel and drain all inflight DMA first,
 * then invoke deinit_module to notify firmware.
 *
 * This intentionally breaks strict init/teardown mirror symmetry due to
 * hardware constraint: firmware may perform asynchronous global hardware
 * cleanup once driver_status=false is set. We must guarantee no ongoing
 * mailbox DMA before deinit_module to avoid invalid DMA write.
 *
 * Init order: create mailbox(common_dev) → ctrl dev init
 * Teardown order: destroy mailbox(common_dev) → ctrl dev deinit
 */
void nbl_dev_remove(struct nbl_adapter *adapter)
{
	struct nbl_common_info *common = &adapter->common;

	nbl_dev_remove_common_dev(adapter);
	if (common->has_ctrl)
		nbl_dev_remove_ctrl_dev(adapter);
}

/* ----------  Dev start process  ---------- */
int nbl_dev_start(struct nbl_adapter *adapter)
{
	struct nbl_dev_mgt *dev_mgt = adapter->core.dev_mgt;
	struct nbl_dispatch_ops *disp_ops = dev_mgt->disp_ops_tbl->ops;
	struct nbl_dispatch_mgt *priv = dev_mgt->disp_ops_tbl->priv;
	struct nbl_dev_common *common_dev = dev_mgt->common_dev;
	struct nbl_common_info *common = dev_mgt->common;
	int cleanup_ret;
	int ret;

	ret = nbl_dev_cfg_msix_map(dev_mgt);
	if (ret)
		goto err_destroy_map;

	/* Fetch VSI/ETH identity after cfg_msix_map */
	ret = disp_ops->get_vsi_id(priv, NBL_VSI_DATA, &common->vsi_id);
	if (ret)
		goto err_destroy_map;
	ret = disp_ops->get_eth_id(priv, common->vsi_id, &common->eth_num,
				   &common->eth_id, &common->logic_eth_id);
	if (ret)
		goto err_destroy_map;

	ret = nbl_dev_init_interrupt_scheme(dev_mgt);
	if (ret)
		goto err_destroy_map;

	ret = nbl_dev_request_mailbox_irq(dev_mgt);
	if (ret)
		goto err_destroy_map;

	ret = nbl_dev_enable_mailbox_irq(dev_mgt);
	if (ret)
		goto err_disable_irq;

	return 0;

err_disable_irq:
	cleanup_ret = nbl_dev_disable_mailbox_irq(dev_mgt);
	if (cleanup_ret)
		dev_err(dev_mgt->common->dev,
			"rollback: disable mailbox IRQ failed: %d\n",
			cleanup_ret);
	nbl_dev_free_mailbox_irq(dev_mgt);
err_destroy_map:
	/*
	 * Destroy device-side MSI-X map BEFORE releasing kernel-side
	 * vectors. This masks all hardware vectors and clears the
	 * pcompleter map entry, so no MSI-X message can fire after
	 * vector release.
	 *
	 * For non-control PFs this is a polling-mode mailbox RPC
	 * (IRQ_RDY already cleared by disable above, or never set).
	 * If the RPC fails the device may remain armed.
	 *
	 * This is best-effort teardown: we still release kernel vectors
	 * even if remote RPC fails. The hardware entry will be reclaimed
	 * by firmware on chip reset.
	 *
	 * Note: pci_clear_master() runs in nbl_probe() core_start_err path,
	 * Also pci_clear_master() on non-control PF
	 * cannot stop DMA using the manager PF's BDF; this is a known
	 * limitation. Stale hardware entries will be reclaimed by firmware
	 * on chip reset.
	 */
	cleanup_ret = nbl_dev_destroy_msix_map(dev_mgt);
	if (cleanup_ret)
		dev_err(dev_mgt->common->dev,
			"rollback: destroy MSI-X map failed: %d\n",
			cleanup_ret);
	nbl_dev_clear_interrupt_scheme(dev_mgt);

	cancel_work_sync(&common_dev->clean_mbx_task);
	return ret;
}

void nbl_dev_stop(struct nbl_adapter *adapter)
{
	struct nbl_dev_mgt *dev_mgt = adapter->core.dev_mgt;
	struct nbl_dev_common *common_dev = dev_mgt->common_dev;
	int ret;

	ret = nbl_dev_disable_mailbox_irq(dev_mgt);
	if (ret)
		dev_err(dev_mgt->common->dev,
			"Failed to disable mailbox IRQ: %d\n", ret);
	nbl_dev_free_mailbox_irq(dev_mgt);

	/*
	 * Destroy hardware MSI-X map BEFORE releasing kernel-side
	 * vectors. Masks all device vectors and clears pcompleter
	 * map entry first.
	 *
	 * This is best-effort teardown: if destroy_msix_map RPC fails,
	 * hardware MSI-X map remains valid. We proceed to release
	 * kernel vectors anyway. Hardware stale entries rely on
	 * firmware cleanup on chip reset.
	 *
	 * pci_clear_master() on non-control PF cannot stop DMA using manager
	 * PF's BDF.
	 */
	ret = nbl_dev_destroy_msix_map(dev_mgt);
	if (ret)
		dev_err(dev_mgt->common->dev,
			"Failed to destroy MSI-X map: %d\n", ret);

	nbl_dev_clear_interrupt_scheme(dev_mgt);

	/*
	 * destroy_msix_map() sends ack-requested messages which may
	 * requeue clean_mbx_task via polling send path.  Drain work
	 * after the operation.
	 */
	cancel_work_sync(&common_dev->clean_mbx_task);
}
