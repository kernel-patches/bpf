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

	/* Reserve one MSI-X vector for the mailbox.  Nothing here
	 * allocates or requests it: vectors are allocated and the handler
	 * attached when the device is started, after probe, from this
	 * count.
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
	 * Disable sequence invariant: clear the software READY flag first,
	 * then mask the hardware interrupt. Must not reverse the order.
	 *
	 * Clearing NBL_CHAN_IRQ_RDY is what makes an interrupt-mode sender
	 * fail fast: nbl_chan_set_queue_state() wakes every per-slot wait
	 * queue on the transition, and nbl_chan_send_msg() tests the flag
	 * ahead of its timeout branch, so the sender returns -EIO right
	 * away instead of waiting out NBL_CHAN_ACK_WAIT_TIME (3s) and
	 * reporting a bogus -ETIMEDOUT / "Channel waiting ack failed".
	 * Masking first would leave the sleeper blocked on an interrupt
	 * that is already masked, i.e. guaranteed to time out.
	 *
	 * This does NOT preserve in-flight ACKs, and must not be described
	 * as doing so: the woken sender gives up and resets its slot to
	 * IDLE, so an ACK arriving afterwards finds a non-WAITING slot and
	 * is dropped by the receive path ("Skip ack invalid status").
	 * Interrupt mode is being torn down here; the guarantee is a
	 * bounded, deterministic failure, not delivery.  In this driver
	 * every ACK-requesting sender runs from probe/remove and the clean
	 * task only sends ACK-less replies, so nothing depends on the
	 * stronger claim today.
	 *
	 * The only caller is nbl_dev_stop(): free_irq() blocks until
	 * any in-flight hardirq handler completes and prevents new interrupts.
	 * cancel_work_sync() then waits for any already running mailbox cleanup
	 * work to finish, or cancels queued but unstarted work items before
	 * final channel destruction. No stuck descriptors linger.
	 *
	 * nbl_dev_start()'s unwind path does not reach here: err_free_irq runs
	 * before IRQ_RDY is set, so only nbl_dev_free_mailbox_irq() applies
	 * there and no set_mailbox_irq(false) is sent - see the comment on
	 * that label.
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
	struct irq_affinity affd = { 0 };
	int needed = 0;
	int err;
	int i;

	for (i = 0; i < NBL_MSIX_TYPE_MAX; i++)
		needed += msix_info->serv_info[i].num;

	/*
	 * The mailbox vector is the trailing administrative vector;
	 * reserve it via post_vectors so it is excluded from managed
	 * affinity spreading. A managed vector can be shut down when
	 * its last assigned CPU goes offline, which would stall every
	 * mailbox RPC while NBL_CHAN_IRQ_RDY stays set.
	 */
	affd.post_vectors = msix_info->serv_info[NBL_MSIX_MAILBOX_TYPE].num;

	err = pci_alloc_irq_vectors_affinity(common->pdev, needed, needed,
					     PCI_IRQ_MSIX | PCI_IRQ_AFFINITY,
					     &affd);
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

/*
 * Release the kernel-side MSI-X vectors here, before the hardware
 * pcompleter map is destroyed.  pci_free_irq_vectors() ends in
 * pci_msix_shutdown(), which masks every descriptor by writing the
 * vector control word in the MSI-X table and then reads mask_base
 * back to flush that write; those MMIO accesses should reach the
 * function while FUNCTION_MSIX_MAP is still valid.  This mirrors
 * nbl_dev_start(), where cfg_msix_map runs before
 * pci_alloc_irq_vectors_affinity(): the opposite order leaves the
 * core poking the MSI-X table after destroy_msix_map() has cleared
 * the valid bit, invalidated the info entries and freed the map
 * table, and how the device reacts to that is hardware-specific.
 *
 * This is not a double free of the devres action.  probe uses
 * pcim_enable_device(), so pci_alloc_irq_vectors() also registers
 * pcim_msi_release, but that only calls pci_free_irq_vectors()
 * again, and pci_disable_msix() returns early once msix_enabled is
 * clear.
 *
 * The handler is expected to be gone by now: both callers run
 * nbl_dev_free_mailbox_irq() first.
 */
static void nbl_dev_clear_interrupt_scheme(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_common_info *common = dev_mgt->common;

	pci_free_irq_vectors(common->pdev);
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
	 * VSI/ETH identity is deliberately not fetched here: it is only
	 * known to the control PF, so it has to come from a mailbox RPC,
	 * and the control PF's responder may still be probing while this
	 * function runs.  The fetch is therefore left to the start path.
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
		return ret;

	if (common->has_ctrl) {
		ret = nbl_dev_setup_ctrl_dev(adapter);
		if (ret)
			goto out_remove_common_dev;
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
out_remove_common_dev:
	nbl_dev_remove_common_dev(adapter);
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

	/*
	 * Startup RPC failures are reported as they are, including the
	 * -ETIMEDOUT of a 5-6s polling wait against an unresponsive peer.
	 * nbl_probe() already deferred this PF in nbl_probe_chip_deps()
	 * until the control PF reached DL_DEV_DRIVER_BOUND, and the core
	 * only marks a device bound once its whole probe - including the
	 * control PF's own nbl_core_start() - has returned.  That state,
	 * not nbl_dev_init(), is what makes a timeout here a real failure
	 * instead of a "supplier not ready yet" condition: on the control
	 * PF inbound mailbox work only runs from clean_mbx_task, queued
	 * by the mailbox hardirq, by the task's own self-requeue, or by
	 * this function's polling sends - and the control PF uses the
	 * local dispatch ops, so it sends none.  The responder is armed
	 * by set_mailbox_irq(true) at the very end of the peer's
	 * nbl_dev_start(); relaxing the dependency to "func 0 finished
	 * nbl_dev_init()" would let every sibling RPC sit out the full
	 * 5-6s polling wait.  Turning -ETIMEDOUT into -EPROBE_DEFER would
	 * hide it behind dev_dbg() and leave the retry to the next
	 * unrelated device bind, paying that wait again on every retry.
	 */
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
		goto err_free_irq;

	return 0;

err_free_irq:
	/*
	 * nbl_dev_enable_mailbox_irq() only fails before it sets
	 * NBL_CHAN_IRQ_RDY - the flag is set after its RPC returns - so
	 * there is no interrupt-mode sender to release and no software
	 * state to revoke.  The peer-side mailbox routing, if the failed
	 * RPC did land, is switched off by the destroy_msix_map() below: its
	 * prepare phase, __nbl_res_intr_prepare_destroy_msix_map(), disables
	 * mailbox IRQ routing for any CONFIGURED function before the map is
	 * torn down.  That is what makes skipping set_mailbox_irq(false)
	 * correct here, whatever way the enable failed - a local
	 * -ESHUTDOWN/-ENODEV/-EINVAL on the control PF as much as a
	 * polling-mode -ETIMEDOUT against an unresponsive peer.
	 */
	nbl_dev_free_mailbox_irq(dev_mgt);
err_destroy_map:
	/*
	 * Always ask the peer to drop this function's MSI-X map, even when
	 * the cfg RPC above failed: the teardown prepare phase returns 0
	 * for a function that is not NBL_INTR_FUNC_CONFIGURED, so it is a
	 * no-op when nothing landed, but a -ETIMEDOUT only means the ACK
	 * never arrived - the responder runs to completion before it ACKs.
	 * In that case the map entry, the intr_net/other_bmap bits, the
	 * kcalloc()ed vector array and the coherent map table are all
	 * still owned by the control PF, i.e. host resources of its
	 * driver, released only when this function is configured again or
	 * when nbl_intr_mgt_stop() tears the control PF down.  They are not
	 * firmware state, so skipping the destroy would strand them for a
	 * PF that has no driver to ever ask for them again.
	 *
	 * Kernel vectors are released first, by the
	 * nbl_dev_clear_interrupt_scheme() below: the PCI core's MSI-X
	 * shutdown writes the MSI-X table and reads it back, and those
	 * accesses should land while this function's pcompleter map entry
	 * is still valid.  The destroy then masks all hardware vectors
	 * and clears that entry.
	 *
	 * For non-control PFs this is a polling-mode mailbox RPC:
	 * NBL_CHAN_IRQ_RDY is never set on any rollback path, since
	 * enabling it is the last step of nbl_dev_start().
	 *
	 * Note: pci_clear_master() runs in nbl_probe() core_start_err path;
	 * on a non-control PF it cannot stop DMA using the management PF's
	 * BDF, this is a known limitation.
	 */
	nbl_dev_clear_interrupt_scheme(dev_mgt);
	cleanup_ret = nbl_dev_destroy_msix_map(dev_mgt);
	if (cleanup_ret)
		dev_err(dev_mgt->common->dev,
			"rollback: destroy MSI-X map failed: %d\n",
			cleanup_ret);

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
	 * Release the kernel vectors before destroying the hardware map:
	 * the PCI core's MSI-X shutdown writes the MSI-X table and reads
	 * it back, and those accesses should land while this function's
	 * pcompleter map entry is still valid (see
	 * nbl_dev_clear_interrupt_scheme).
	 */
	nbl_dev_clear_interrupt_scheme(dev_mgt);

	/*
	 * Destroy the hardware MSI-X map: masks all device vectors and
	 * clears the pcompleter map entry.
	 *
	 * Best-effort: if the destroy RPC fails, the control PF still owns
	 * this function's map entry, its intr_net/other_bmap bits and its
	 * coherent map table.  Those are host resources of that driver,
	 * released either by a later successful configuration of this
	 * function - nbl_res_intr_cfg_msix_map() invalidates and rewrites
	 * the entry on its had_config path - or by nbl_intr_mgt_stop()
	 * when the control PF is removed, which walks every
	 * NBL_INTR_FUNC_CONFIGURED function through
	 * __nbl_res_intr_prepare_destroy_msix_map() and clears the
	 * FUNCTION_MSIX_MAP valid bit.  Both rewrite the hardware entry
	 * without a chip reset; nothing else collects it, so a stranded
	 * one just stays as it is, and nothing requests one.
	 *
	 * pci_clear_master() on a non-control PF cannot stop DMA using the
	 * management PF's BDF.
	 */
	ret = nbl_dev_destroy_msix_map(dev_mgt);
	if (ret)
		dev_err(dev_mgt->common->dev,
			"Failed to destroy MSI-X map: %d\n", ret);

	/*
	 * destroy_msix_map() sends ack-requested messages which may
	 * requeue clean_mbx_task via polling send path.  Drain work
	 * after the operation.
	 */
	cancel_work_sync(&common_dev->clean_mbx_task);
}
