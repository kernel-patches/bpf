// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Nebula Matrix Limited.
 */
#include <linux/device.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/bitfield.h>
#include "nbl_interrupt.h"

#define NBL_MSIX_DMA_SYNC_MIN_US	1000 /* us */
#define NBL_MSIX_DMA_SYNC_MAX_US	1200 /* us */

/*
 * Release global vector IDs back to intr_net_bmap / intr_other_bmap.
 * Caller must hold intr_mgt->lock.
 */
static void nbl_intr_release_bitmap(struct nbl_resource_mgt *res_mgt,
				    u16 *vec_buf, u16 cnt)
{
	struct nbl_interrupt_mgt *intr_mgt = res_mgt->intr_mgt;
	u16 bit;
	u16 i;

	lockdep_assert_held(&intr_mgt->lock);

	if (!vec_buf || cnt == 0)
		return;

	for (i = 0; i < cnt; i++) {
		u16 intr_index = vec_buf[i];

		if (intr_index >= NBL_NET_INTR_BASE) {
			bit = intr_index - NBL_NET_INTR_BASE;
			if (bit < NBL_MAX_NET_INTERRUPT)
				clear_bit(bit, intr_mgt->intr_net_bmap);
			else
				dev_warn(res_mgt->common->dev,
					 "invalid net intr index %u\n",
					 intr_index);
		} else {
			if (intr_index < NBL_MAX_OTHER_INTERRUPT)
				clear_bit(intr_index,
					  intr_mgt->intr_other_bmap);
			else
				dev_warn(res_mgt->common->dev,
					 "invalid other intr index %u\n",
					 intr_index);
		}
	}
}

/*
 * Internal (unlocked) mailbox IRQ bind.  Caller must hold
 * intr_mgt->lock.  The disable path does not require a configured
 * MSI-X map because the hardware op ignores gvec when
 * en_msix=false.
 */
static int __nbl_res_intr_set_mailbox_irq(struct nbl_resource_mgt *res_mgt,
					  u16 func_id, u16 vector_id,
					  bool en_msix)
{
	struct nbl_interrupt_mgt *intr_mgt = res_mgt->intr_mgt;
	struct nbl_hw_ops *hw_ops = res_mgt->hw_ops_tbl->ops;
	struct nbl_common_info *common = res_mgt->common;
	struct device *dev = common->dev;
	struct nbl_func_interrupt_resource_mng *func_res;
	u16 gvec;

	lockdep_assert_held(&intr_mgt->lock);

	if (func_id >= NBL_MAX_FUNC) {
		dev_err(dev, "func_id %u out of range\n", func_id);
		return -EINVAL;
	}

	if (!en_msix) {
		hw_ops->set_mailbox_irq(res_mgt->hw_ops_tbl->priv,
					func_id, false, 0);
		hw_ops->flush_write(res_mgt->hw_ops_tbl->priv);
		return 0;
	}

	/*
	 * Enable path: the map must be live and not under teardown,
	 * otherwise routing would point at a vector that the complete
	 * phase is about to release and never re-disables.
	 */
	if (intr_mgt->stopping)
		return -ESHUTDOWN;

	func_res = &intr_mgt->func_intr_res[func_id];
	if (func_res->state != NBL_INTR_FUNC_CONFIGURED) {
		dev_err(dev, "func %u MSIX map not configured (state %u)\n",
			func_id, func_res->state);
		return -ENODEV;
	}

	if (vector_id >= func_res->num_interrupts) {
		dev_err(dev, "vector_id %u out of range (max %u)\n",
			vector_id, func_res->num_interrupts - 1);
		return -EINVAL;
	}

	gvec = func_res->interrupts[vector_id];
	hw_ops->set_mailbox_irq(res_mgt->hw_ops_tbl->priv, func_id,
				en_msix, gvec);
	hw_ops->flush_write(res_mgt->hw_ops_tbl->priv);

	return 0;
}

/*
 * Internal (unlocked) MSI-X map teardown prepare phase: only hardware
 * register operations. The DMA address is retained and only the VALID
 * bit is cleared; zeroing the address (Stage 2) is deferred to the
 * complete phase after the hardware-DMA quiesce window.
 *
 * Caller must hold intr_mgt->lock.
 */
static int
__nbl_res_intr_prepare_destroy_msix_map(struct nbl_resource_mgt *res_mgt,
					u16 func)
{
	struct nbl_interrupt_mgt *intr_mgt = res_mgt->intr_mgt;
	struct nbl_hw_ops *hw_ops = res_mgt->hw_ops_tbl->ops;
	struct nbl_func_interrupt_resource_mng *func_res;
	u16 *interrupts;
	u16 intr_num, i;
	int ret;

	lockdep_assert_held(&intr_mgt->lock);

	if (func >= NBL_MAX_FUNC) {
		dev_err(res_mgt->common->dev, "Invalid func_id %u\n", func);
		return -EINVAL;
	}

	func_res = &intr_mgt->func_intr_res[func];
	if (func_res->state != NBL_INTR_FUNC_CONFIGURED)
		return 0;

	interrupts = func_res->interrupts;
	intr_num = func_res->num_interrupts;

	/* Step 0: disable mailbox IRQ routing before tearing down map */
	ret = __nbl_res_intr_set_mailbox_irq(res_mgt, func, 0, false);
	if (ret) {
		dev_err(res_mgt->common->dev,
			"disable mailbox irq failed, func=%u ret=%d\n",
			func, ret);
		return ret;
	}

	/* Step 1: invalidate each MSIX info entry in hardware first */
	for (i = 0; i < intr_num; i++) {
		hw_ops->cfg_msix_info(res_mgt->hw_ops_tbl->priv,
				      func, false, interrupts[i],
				      0, 0, 0, false);
	}
	hw_ops->flush_write(res_mgt->hw_ops_tbl->priv);

	/*
	 * Stage 1: retain the DMA address, only clear the VALID bit.
	 * Stage 2 runs after the quiesce window in the complete phase.
	 */
	hw_ops->cfg_msix_map(res_mgt->hw_ops_tbl->priv, func,
			     false, func_res->msix_map_table.dma,
			     0, 0, 0);
	hw_ops->flush_write(res_mgt->hw_ops_tbl->priv);

	func_res->state = NBL_INTR_FUNC_DESTROYING;

	return 0;
}

/*
 * __nbl_res_intr_complete_destroy_msix_map - finish hardware teardown and
 * release vector bitmap, DMA memory and interrupt buffer after the
 * hardware quiesce window has elapsed.
 *
 * Caller must hold intr_mgt->lock.
 */
static int
__nbl_res_intr_complete_destroy_msix_map(struct nbl_resource_mgt *res_mgt,
					 u16 func_id)
{
	struct nbl_interrupt_mgt *intr_mgt = res_mgt->intr_mgt;
	struct nbl_hw_ops *hw_ops = res_mgt->hw_ops_tbl->ops;
	struct nbl_func_interrupt_resource_mng *func_res;
	struct nbl_msix_map_table *msix_map_table;
	struct device *dev = res_mgt->common->dev;
	u16 *interrupts;
	u16 intr_num;

	lockdep_assert_held(&intr_mgt->lock);

	if (func_id >= NBL_MAX_FUNC) {
		dev_err(dev, "Invalid func_id %u\n", func_id);
		return -EINVAL;
	}

	func_res = &intr_mgt->func_intr_res[func_id];
	if (func_res->state != NBL_INTR_FUNC_DESTROYING)
		return 0;

	/*
	 * Stage 2: the quiesce window has elapsed, it is now safe to
	 * zero the DMA base address in the hardware map register.
	 */
	hw_ops->cfg_msix_map(res_mgt->hw_ops_tbl->priv, func_id,
			     false, 0, 0, 0, 0);
	hw_ops->flush_write(res_mgt->hw_ops_tbl->priv);

	interrupts = func_res->interrupts;
	intr_num = func_res->num_interrupts;
	msix_map_table = &func_res->msix_map_table;

	if (interrupts) {
		nbl_intr_release_bitmap(res_mgt, interrupts, intr_num);
		kfree(interrupts);
	}

	/*
	 * Release the coherent table independently of interrupts so a
	 * partially built config (table allocated, vectors never
	 * published) cannot leak coherent DMA memory.
	 */
	if (msix_map_table->base_addr) {
		dma_free_coherent(dev, msix_map_table->size,
				  msix_map_table->base_addr,
				  msix_map_table->dma);
		msix_map_table->base_addr = NULL;
		msix_map_table->dma = 0;
		msix_map_table->size = 0;
	}

	func_res->interrupts = NULL;
	func_res->num_interrupts = 0;
	func_res->num_net_interrupts = 0;
	func_res->state = NBL_INTR_FUNC_IDLE;

	return 0;
}

/*
 * Internal (unlocked) MSI-X map teardown.  Caller must hold
 * intr_mgt->lock for the whole sequence, including the hardware-DMA
 * quiesce window: dropping the lock would let a concurrent caller (or
 * nbl_intr_mgt_stop()) install/free state against this teardown.
 *
 * This is used for the single function synchronous destroy path.
 */
static int __nbl_res_intr_destroy_msix_map(struct nbl_resource_mgt *res_mgt,
					   u16 func_id)
{
	struct nbl_interrupt_mgt *intr_mgt = res_mgt->intr_mgt;
	int ret;

	lockdep_assert_held(&intr_mgt->lock);

	if (intr_mgt->stopping)
		return -ESHUTDOWN;

	ret = __nbl_res_intr_prepare_destroy_msix_map(res_mgt, func_id);
	if (ret)
		return ret;
	/*
	 * prepare() only transitions CONFIGURED functions; an IDLE func
	 * has nothing to wait for or complete.
	 */
	if (intr_mgt->func_intr_res[func_id].state !=
	    NBL_INTR_FUNC_DESTROYING)
		return 0;

	usleep_range(NBL_MSIX_DMA_SYNC_MIN_US, NBL_MSIX_DMA_SYNC_MAX_US);

	return __nbl_res_intr_complete_destroy_msix_map(res_mgt, func_id);
}

int nbl_res_intr_destroy_msix_map(struct nbl_resource_mgt *res_mgt,
				  u16 func_id)
{
	struct nbl_interrupt_mgt *intr_mgt = res_mgt->intr_mgt;
	int ret;

	if (!intr_mgt)
		return -EINVAL;

	mutex_lock(&intr_mgt->lock);
	ret = __nbl_res_intr_destroy_msix_map(res_mgt, func_id);
	mutex_unlock(&intr_mgt->lock);

	return ret;
}

/**
 * nbl_res_intr_cfg_msix_map - allocate & program MSI-X mapping table
 * @res_mgt: resource management instance
 * @func_id: target function identifier
 * @num_net_msix: required net data interrupt vectors
 * @num_others_msix: required control interrupt vectors
 * @net_msix_mask_en: enable mask for net interrupt entries
 *
 * Allocate interrupt vectors; MSIX coherent DMA table is allocated once
 * per function on first configuration, entries are rewritten while the
 * map is invalidated on subsequent reconfigurations. No free/realloc of
 * DMA table on vector count changes. This removes the DMA table
 * free/realloc cycle. On reconfiguration the map VALID bit is cleared
 * and the hardware-DMA quiesce window is observed (lock held) before old
 * vectors are recycled and the table is rewritten.
 *
 * Serialization: this function takes intr_mgt->lock internally to
 * protect the global vector bitmaps and per-function state against
 * concurrent callers.
 *
 * Return: 0 on success, negative errno on failure
 */
int nbl_res_intr_cfg_msix_map(struct nbl_resource_mgt *res_mgt,
			      u16 func_id, u16 num_net_msix,
			      u16 num_others_msix,
			      bool net_msix_mask_en)
{
	struct nbl_interrupt_mgt *intr_mgt = res_mgt->intr_mgt;
	struct nbl_hw_ops *hw_ops = res_mgt->hw_ops_tbl->ops;
	struct nbl_common_info *common = res_mgt->common;
	struct nbl_msix_map_table *official_tbl;
	struct nbl_msix_map *msix_map_entries;
	struct device *dev = common->dev;
	u16 requested, intr_index;
	u8 bus, devid, function;
	bool entry_masked = false;
	u16 *tmp_interrupts = NULL;
	u16 allocated_cnt = 0;
	u16 *old_interrupts;
	u16 old_num;
	bool had_config;
	int ret = 0;
	u16 gvec;
	u16 i, j;

	if (!intr_mgt)
		return -EINVAL;

	if (!common->has_ctrl)
		return -EINVAL;

	if (func_id >= NBL_MAX_FUNC) {
		dev_err(dev, "Invalid func_id %u\n", func_id);
		return -EINVAL;
	}

	if (num_net_msix == 0 && num_others_msix == 0) {
		dev_err(dev, "MSI-X vector count cannot both be zero\n");
		return -EINVAL;
	}

	if (num_net_msix > NBL_MSIX_MAP_TABLE_MAX_ENTRIES ||
	    num_others_msix > NBL_MSIX_MAP_TABLE_MAX_ENTRIES) {
		dev_err(dev, "MSI-X count out of limit: net=%u, others=%u\n",
			num_net_msix, num_others_msix);
		return -EINVAL;
	}

	if (check_add_overflow(num_net_msix, num_others_msix, &requested) ||
	    requested > NBL_MSIX_MAP_TABLE_MAX_ENTRIES) {
		dev_err(dev, "Total MSI-X vectors %u exceeds maximum %u\n",
			requested, NBL_MSIX_MAP_TABLE_MAX_ENTRIES);
		return -EINVAL;
	}

	ret = nbl_res_func_id_to_bdf(res_mgt, func_id, &bus, &devid, &function);
	if (ret) {
		if (ret == -EOPNOTSUPP)
			dev_err(dev,
				"MSI-X mapping for VF func_id=%u is not supported\n",
				func_id);
		return ret;
	}

	mutex_lock(&intr_mgt->lock);
	official_tbl = &intr_mgt->func_intr_res[func_id].msix_map_table;

	/* Reject new configs during teardown or while func is mid-destroy */
	if (intr_mgt->stopping) {
		ret = -ESHUTDOWN;
		goto out_unlock;
	}
	if (intr_mgt->func_intr_res[func_id].state ==
	    NBL_INTR_FUNC_DESTROYING) {
		ret = -EBUSY;
		goto out_unlock;
	}

	had_config = intr_mgt->func_intr_res[func_id].state ==
		     NBL_INTR_FUNC_CONFIGURED;

	/*
	 * Phase1: allocate global vector array first.
	 * Allocate the fixed-size MSIX DMA table only ONCE for this function.
	 */
	tmp_interrupts = kcalloc(requested, sizeof(*tmp_interrupts),
				 GFP_KERNEL);
	if (!tmp_interrupts) {
		ret = -ENOMEM;
		goto out_unlock;
	}
	/* Allocate MSIX DMA table once per function */
	if (!official_tbl->base_addr) {
		official_tbl->size =
			sizeof(struct nbl_msix_map) *
			NBL_MSIX_MAP_TABLE_MAX_ENTRIES;
		official_tbl->base_addr = dma_alloc_coherent(dev,
							     official_tbl->size,
							     &official_tbl->dma,
							     GFP_KERNEL);
		if (!official_tbl->base_addr) {
			dev_err(dev, "Failed to allocate DMA memory for MSIX table\n");
			ret = -ENOMEM;
			goto release_vecs_unlock;
		}
	}

	/* Allocate net interrupt vectors */
	for (i = 0; i < num_net_msix; i++) {
		intr_index = find_first_zero_bit(intr_mgt->intr_net_bmap,
						 NBL_MAX_NET_INTERRUPT);
		if (intr_index == NBL_MAX_NET_INTERRUPT) {
			dev_err(dev, "No free net interrupt vectors left\n");
			ret = -EAGAIN;
			goto release_vecs_unlock;
		}
		tmp_interrupts[i] = intr_index + NBL_NET_INTR_BASE;
		set_bit(intr_index, intr_mgt->intr_net_bmap);
		allocated_cnt++;
	}

	/* Allocate other interrupt vectors */
	for (; i < requested; i++) {
		intr_index =
			find_first_zero_bit(intr_mgt->intr_other_bmap,
					    NBL_MAX_OTHER_INTERRUPT);
		if (intr_index == NBL_MAX_OTHER_INTERRUPT) {
			dev_err(dev, "No free control interrupt vectors left\n");
			ret = -EAGAIN;
			goto release_vecs_unlock;
		}
		tmp_interrupts[i] = intr_index;
		set_bit(intr_index, intr_mgt->intr_other_bmap);
		allocated_cnt++;
	}

	/*
	 * Phase2: quiesce the old hardware MSIX config before touching
	 * the live DMA table. Same sequence as destroy:
	 *   disable mailbox routing -> invalidate per-vector INFO ->
	 *   clear map VALID -> flush -> wait for in-flight table fetches.
	 * The lock stays held across the wait, so no concurrent caller
	 * can program the quiesced function. Only then are old vectors
	 * recycled.
	 * NOTE: NO DMA table free here.
	 */
	if (had_config) {
		old_interrupts =
			intr_mgt->func_intr_res[func_id].interrupts;
		old_num = intr_mgt->func_intr_res[func_id].num_interrupts;

		ret = __nbl_res_intr_set_mailbox_irq(res_mgt, func_id, 0,
						     false);
		if (ret) {
			dev_err(dev, "%s: disable old mailbox irq failed, keep old config\n",
				__func__);
			goto release_vecs_unlock;
		}
		for (j = 0; j < old_num; j++) {
			hw_ops->cfg_msix_info(res_mgt->hw_ops_tbl->priv,
					      func_id, false,
					      old_interrupts[j],
					      0, 0, 0, false);
		}
		hw_ops->cfg_msix_map(res_mgt->hw_ops_tbl->priv, func_id,
				     false, official_tbl->dma,
				     0, 0, 0);
		hw_ops->flush_write(res_mgt->hw_ops_tbl->priv);

		usleep_range(NBL_MSIX_DMA_SYNC_MIN_US,
			     NBL_MSIX_DMA_SYNC_MAX_US);

		nbl_intr_release_bitmap(res_mgt, old_interrupts, old_num);
		kfree(old_interrupts);
		intr_mgt->func_intr_res[func_id].interrupts = NULL;
		intr_mgt->func_intr_res[func_id].num_interrupts = 0;
		intr_mgt->func_intr_res[func_id].num_net_interrupts = 0;
	}

	/* Swap new vector array into func state */
	intr_mgt->func_intr_res[func_id].interrupts = tmp_interrupts;
	intr_mgt->func_intr_res[func_id].num_interrupts = requested;
	intr_mgt->func_intr_res[func_id].num_net_interrupts = num_net_msix;
	tmp_interrupts = NULL;

	/*
	 * Rewrite the table in the pre-allocated DMA buffer while the
	 * map is invalid (on reconfig) or not yet valid (on fresh config),
	 * so the device cannot observe a torn old/new mix. Only entries
	 * beyond requested count need explicit zeroing.
	 */
	msix_map_entries = official_tbl->base_addr;
	memset(msix_map_entries + requested, 0,
	       (NBL_MSIX_MAP_TABLE_MAX_ENTRIES - requested) *
	       sizeof(*msix_map_entries));

	for (i = 0; i < requested; i++) {
		gvec = intr_mgt->func_intr_res[func_id].interrupts[i];
		msix_map_entries[i].data =
			cpu_to_le16(FIELD_PREP(NBL_MSIX_MAP_VALID_MASK, 1) |
				    FIELD_PREP(NBL_MSIX_MAP_INDEX_MASK,
					       gvec));
	}

	/* Ensure coherent table writes are visible before HW fetch/enable */
	dma_wmb();

	/* Enable per-vector INFO entries after the table is published */
	for (i = 0; i < requested; i++) {
		gvec = intr_mgt->func_intr_res[func_id].interrupts[i];
		entry_masked = (i < num_net_msix && net_msix_mask_en);
		hw_ops->cfg_msix_info(res_mgt->hw_ops_tbl->priv,
				      func_id, true, gvec,
				      bus, devid, function,
				      entry_masked);
	}
	hw_ops->flush_write(res_mgt->hw_ops_tbl->priv);

	/*
	 * Point the map at the table last and set VALID.
	 *
	 * cfg_msix_map uses the control PF's own BDF (common->hw_bus etc.),
	 * not the target function's BDF.  This BDF tags the pcompler DMA
	 * read of the MSI-X map table as originating from the control PF.
	 * The target function's BDF (bus/devid/function from
	 * nbl_res_func_id_to_bdf) is used only in cfg_msix_info for the
	 * host_msix_ctrl table entry BDF filtering.
	 */
	hw_ops->cfg_msix_map(res_mgt->hw_ops_tbl->priv, func_id,
			     true, official_tbl->dma, common->hw_bus,
			     common->devid, common->function);
	hw_ops->flush_write(res_mgt->hw_ops_tbl->priv);

	intr_mgt->func_intr_res[func_id].state = NBL_INTR_FUNC_CONFIGURED;
	mutex_unlock(&intr_mgt->lock);
	return 0;

release_vecs_unlock:
	nbl_intr_release_bitmap(res_mgt, tmp_interrupts, allocated_cnt);
	kfree(tmp_interrupts);
	/*
	 * On a failed fresh configuration, release the DMA table
	 * allocated during this call. On a failed reconfiguration the
	 * old configuration is still intact (it is only torn down
	 * after all vector allocations succeed) and owns the table.
	 */
	if (!had_config && official_tbl->base_addr) {
		dma_free_coherent(dev, official_tbl->size,
				  official_tbl->base_addr,
				  official_tbl->dma);
		official_tbl->base_addr = NULL;
		official_tbl->dma = 0;
		official_tbl->size = 0;
	}
out_unlock:
	mutex_unlock(&intr_mgt->lock);
	return ret;
}

/**
 * nbl_res_intr_set_mailbox_irq - bind mailbox IRQ to specified vector
 * @res_mgt: resource management instance
 * @func_id: target function identifier
 * @vector_id: index inside local interrupt array
 * @en_msix: enable/disable mailbox interrupt
 *
 * Serialization: takes intr_mgt->lock internally.
 *
 * Return: 0 on success, negative errno on parameter or state check
 * failure.  The hardware op is void and cannot report failure.
 */
int nbl_res_intr_set_mailbox_irq(struct nbl_resource_mgt *res_mgt,
				 u16 func_id, u16 vector_id,
				 bool en_msix)
{
	struct nbl_interrupt_mgt *intr_mgt = res_mgt->intr_mgt;
	struct nbl_common_info *common = res_mgt->common;
	int ret;

	if (!intr_mgt)
		return -EINVAL;

	if (!common->has_ctrl)
		return -EINVAL;

	mutex_lock(&intr_mgt->lock);
	ret = __nbl_res_intr_set_mailbox_irq(res_mgt, func_id,
					     vector_id, en_msix);
	mutex_unlock(&intr_mgt->lock);

	return ret;
}

static struct nbl_interrupt_mgt *nbl_intr_setup_mgt(struct device *dev)
{
	struct nbl_interrupt_mgt *intr_mgt;
	int err;

	intr_mgt = devm_kzalloc(dev, sizeof(*intr_mgt), GFP_KERNEL);
	if (!intr_mgt)
		return ERR_PTR(-ENOMEM);

	err = devm_mutex_init(dev, &intr_mgt->lock);
	if (err)
		return ERR_PTR(err);

	intr_mgt->stopping = false;
	bitmap_zero(intr_mgt->intr_net_bmap, NBL_MAX_NET_INTERRUPT);
	bitmap_zero(intr_mgt->intr_other_bmap, NBL_MAX_OTHER_INTERRUPT);

	return intr_mgt;
}

int nbl_intr_mgt_start(struct nbl_resource_mgt *res_mgt)
{
	struct device *dev = res_mgt->common->dev;
	struct nbl_interrupt_mgt *intr_mgt;
	int ret;

	intr_mgt = nbl_intr_setup_mgt(dev);
	if (IS_ERR(intr_mgt)) {
		ret = PTR_ERR(intr_mgt);
		return ret;
	}

	res_mgt->intr_mgt = intr_mgt;
	return 0;
}

void nbl_intr_mgt_stop(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_interrupt_mgt *intr_mgt = res_mgt->intr_mgt;
	u16 func_id;
	int ret;

	if (!intr_mgt)
		return;

	/*
	 * Phase 1: batch invalidate all hardware MSIX map entries.
	 * stopping is set under the lock, so any caller racing with the
	 * quiesce window below either holds the lock and sees stopping
	 * at its next checkpoint, or acquires it after this phase and
	 * fails (-ESHUTDOWN/-EBUSY/-ENODEV) before issuing MMIO.
	 */
	mutex_lock(&intr_mgt->lock);
	intr_mgt->stopping = true;
	for (func_id = 0; func_id < NBL_MAX_FUNC; func_id++) {
		if (intr_mgt->func_intr_res[func_id].state ==
		    NBL_INTR_FUNC_CONFIGURED) {
			dev_info(res_mgt->common->dev,
				 "intr_mgt_stop: preparing destroy map for func %u\n",
				 func_id);
			ret = __nbl_res_intr_prepare_destroy_msix_map(res_mgt,
								      func_id);
			if (ret)
				dev_warn(res_mgt->common->dev,
					 "intr_mgt_stop: prepare destroy map for func %u failed: %d\n",
					 func_id, ret);
		}
	}
	mutex_unlock(&intr_mgt->lock);

	/*
	 * Global quiesce: wait for straggler DMA table reads after all
	 * MSIX map entries have been invalidated in hardware, before
	 * freeing coherent memory. Best-effort only.
	 */
	usleep_range(NBL_MSIX_DMA_SYNC_MIN_US, NBL_MSIX_DMA_SYNC_MAX_US);

	/* Phase2: safely release MSIX coherent memory and intr resources */
	mutex_lock(&intr_mgt->lock);
	for (func_id = 0; func_id < NBL_MAX_FUNC; func_id++) {
		if (intr_mgt->func_intr_res[func_id].state ==
		    NBL_INTR_FUNC_DESTROYING) {
			ret = __nbl_res_intr_complete_destroy_msix_map(res_mgt,
								       func_id);
			if (ret)
				dev_warn(res_mgt->common->dev,
					 "intr_mgt_stop: complete destroy map for func %u failed: %d\n",
					 func_id, ret);
		}
	}
	/* Clear the published pointer under the lock, last */
	res_mgt->intr_mgt = NULL;
	mutex_unlock(&intr_mgt->lock);
}
