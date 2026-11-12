// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Nebula Matrix Limited.
 */
#include <linux/device.h>
#include <linux/pci.h>
#include "nbl_dev.h"

static void nbl_dev_init_msix_cnt(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_dev_common *dev_common = dev_mgt->common_dev;
	struct nbl_msix_info *msix_info = &dev_common->msix_info;

	/*
	 * Reserve one MSI-X vector for the mailbox.  Nothing here
	 * allocates or requests it: the start path, still inside probe,
	 * uses this count to allocate the vectors and attach the handler.
	 */
	msix_info->serv_info[NBL_MSIX_MAILBOX_TYPE].num = 1;
}

/* ----------  Channel config  ---------- */
static void nbl_dev_setup_chan_qinfo(struct nbl_dev_mgt *dev_mgt, u8 chan_type)
{
	struct nbl_channel_ops *chan_ops = dev_mgt->chan_ops_tbl->ops;
	struct nbl_channel_mgt *priv = dev_mgt->chan_ops_tbl->priv;
	struct nbl_common_info *common = dev_mgt->common;

	if (!chan_ops->check_queue_exist(priv, chan_type))
		return;

	/*
	 * common->hw_bus is the control PF's real bus number, captured in
	 * nbl_res_ctrl_dev_sriov_info_init() during nbl_res_init_leonis().
	 * nbl_core_init() runs resource init before nbl_dev_init(), so the
	 * value is always initialized when this control-PF-only path runs;
	 * nbl_res_intr_cfg_msix_map() consumes it for cfg_msix_map() the
	 * same way.
	 */
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

	/*
	 * INIT_WORK must precede nbl_dev_register_chan_task() below:
	 * registration publishes the work item to the channel, and the
	 * channel may queue it from its send and receive paths as soon
	 * as setup_queue() completes.
	 */
	INIT_WORK(&common_dev->clean_mbx_task, nbl_dev_clean_mailbox_task);

	ret = nbl_dev_setup_chan_queue(dev_mgt, NBL_CHAN_TYPE_MAILBOX);
	if (ret) {
		/*
		 * Nothing to unwind: chan_info->active is only set on a
		 * successful setup_queue(), so a failed one left no
		 * sender, no registered work item and no mailbox
		 * traffic.  Calling teardown_queue() here would only
		 * take its "channel not active" early exit and emit a
		 * misleading duplicate-teardown warning.  The partially
		 * allocated DMA rings are intentionally kept until devres
		 * releases them at detach (chan_info->dma_allocated
		 * blocks a re-setup).
		 */
		return ret;
	}

	nbl_dev_register_chan_task(dev_mgt, NBL_CHAN_TYPE_MAILBOX,
				   &common_dev->clean_mbx_task);
	/*
	 * VSI/ETH identity is deliberately not fetched here but in the
	 * start path, which is where it is used: the IDs only feed MSI-X
	 * and queue setup.  Responder availability is not what defers it -
	 * nbl_probe_chip_deps() keeps a sibling in -EPROBE_DEFER until
	 * func 0 is bound, and driver_bound() only runs after func 0's
	 * whole probe, this function included, has returned.
	 */
	dev_mgt->common_dev = common_dev;
	nbl_dev_init_msix_cnt(dev_mgt);

	return 0;
}

static void nbl_dev_remove_common_dev(struct nbl_adapter *adapter)
{
	struct nbl_dev_mgt *dev_mgt = adapter->core.dev_mgt;
	struct nbl_dev_common *common_dev = dev_mgt->common_dev;

	if (!common_dev)
		return;
	cancel_work_sync(&common_dev->clean_mbx_task);
	/*
	 * nbl_chan_teardown_queue() never fails: it returns 0 both on the
	 * early exit for a channel that never became active and on the
	 * normal path, which drains every inflight sender before
	 * returning.  There is therefore no partial-failure state that
	 * could leave mailbox DMA in flight and nothing to report here.
	 *
	 * Unregistering the clean task is the channel layer's job too:
	 * teardown_queue() clears clean_task under state_lock and then
	 * cancel_work_sync()es it, after shutdn has blocked new queues.
	 * No explicit unregistration is needed here precisely because
	 * teardown_queue() does that clearing itself.  Passing NULL from
	 * here would not be a no-op either: shutdn is only set inside
	 * teardown_queue(), so nbl_chan_register_chan_task() would still
	 * accept the write - it would just be clearing the same pointer a
	 * second time.
	 */
	nbl_dev_remove_chan_queue(dev_mgt, NBL_CHAN_TYPE_MAILBOX);
}

static int nbl_dev_setup_ctrl_dev(struct nbl_adapter *adapter)
{
	struct nbl_dev_mgt *dev_mgt = adapter->core.dev_mgt;
	struct nbl_dispatch_ops *disp_ops = dev_mgt->disp_ops_tbl->ops;

	return disp_ops->init_module(dev_mgt->disp_ops_tbl->priv);
}

/*
 * Tear down control device: deinit_module sets driver_status=false
 * to notify firmware to clean all per-PF hardware state (including
 * qinfo registers).  The qinfo map programmed in nbl_dev_init() via
 * nbl_dev_setup_chan_qinfo() is not explicitly cleared; firmware
 * handles it on driver_status change.
 *
 * Teardown ordering guarantee: every non-management PF creates a
 * consumer->control PF device link in its probe path, so the driver
 * core always unbinds all siblings before allowing the control PF to
 * be detached (sysfs unbind, driver unregister and hot-unplug alike).
 * nbl_probe_chip_deps() defers a sibling's probe until the control PF
 * is fully bound (DL_DEV_DRIVER_BOUND), and holds the management PF's
 * device lock across both that check and device_link_add(), so a
 * supplier cannot slip to DL_DEV_NO_DRIVER or DL_DEV_PROBING in
 * between.  A sibling therefore cannot
 * reach its mailbox setup before the control PF is fully probed, nor
 * race this deinit afterwards - the link forces it to be unbound
 * first.  The link is a persistent managed link with
 * DL_FLAG_AUTOPROBE_CONSUMER, so binding the control PF again makes
 * the core re-probe the siblings; without it they would stay unbound
 * until an admin rebound each one by hand.
 *
 * Direct control-PF FLR (which never runs driver teardown) cannot be
 * guarded here.
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
	if (common->has_ctrl)
		nbl_dev_setup_chan_qinfo(dev_mgt, NBL_CHAN_TYPE_MAILBOX);
	/*
	 * Chip hardware initialization is completed by firmware at power-up.
	 * Only driver functional table/register config follows here, safe to
	 * access hardware registers before ctrl dev setup.
	 *
	 * The QINFO routing has to be programmed before the mailbox queue is
	 * enabled: nbl_dev_setup_common_dev() sets QUEUE_EN, and a queue that
	 * is live before its routing is in place would drop or misroute
	 * traffic.
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
/*
 * A failure after the QINFO routing was programmed leaves those entries
 * in hardware: driver_status never goes 1 -> 0 on these paths, so
 * firmware does not reclaim them.  This is harmless - firmware only
 * routes once driver_status announces the driver, and no sibling PF can
 * bind until this probe succeeds.  The next successful probe overwrites
 * the entries, and a chip reset clears them.
 */
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
 * a hardware constraint: firmware performs asynchronous *per-PF* cleanup
 * (mailbox QINFO routing, qinfo registers and the like) once
 * driver_status=false is set.  It does not revert the chip-wide
 * datapath registers configured by init_module - those stay valid until
 * chip reset (see nbl_hw_deinit_module()).  We must guarantee no ongoing
 * mailbox DMA before deinit_module so firmware cannot reclaim the
 * routing under a live transfer and leave the device DMAing into
 * released memory.
 *
 * Init order: program mailbox QINFO routing (ctrl PF only) ->
 *            create mailbox queue/common_dev -> ctrl dev init_module
 * Teardown order: destroy mailbox queue/common_dev -> ctrl dev deinit_module
 */
void nbl_dev_remove(struct nbl_adapter *adapter)
{
	struct nbl_common_info *common = &adapter->common;

	nbl_dev_remove_common_dev(adapter);
	if (common->has_ctrl)
		nbl_dev_remove_ctrl_dev(adapter);
}
