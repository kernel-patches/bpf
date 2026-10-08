// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.

#include <linux/bitops.h>
#include <linux/dma-mapping.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/interrupt.h>
#include <linux/log2.h>
#include <linux/pci.h>
#include <net/netdev_lock.h>
#include <net/net_namespace.h>

#include "en.h"
#include "nodnic_ifc.h"
#include "nodnic.h"
#include "nodnic_pci_vsc.h"
#include "rx.h"
#include "tx.h"

#define MLX5_NODNIC_CQ_INIT_CMD_SN cpu_to_be32(2 << 28)

static int mlx5_nodnic_write_ring_addr(struct mlx5_nodnic_core_dev *dev,
				       dma_addr_t dma_handle, u32 offset_h,
				       u32 offset_l)
{
	__be32 addr_h, addr_l;
	int err;

	addr_h = cpu_to_be32(upper_32_bits(dma_handle));
	err = mlx5_nodnic_vsc_cfg_write_be32(dev->vsc_ctx, offset_h, addr_h);
	if (err) {
		mlx5_nodnic_core_err(dev,
				     "failed to write ring addr high: %d\n",
				     err);
		return err;
	}

	addr_l = 0;
	MLX5_SET(nodnic_q_addr_l, &addr_l, q_addr_l,
		 lower_32_bits(dma_handle) >> 12);

	err = mlx5_nodnic_vsc_cfg_write_be32(dev->vsc_ctx, offset_l, addr_l);
	if (err)
		mlx5_nodnic_core_err(dev, "failed to write ring addr low: %d\n",
				     err);
	return err;
}

static u32 mlx5_nodnic_calc_ring_size(struct mlx5_nodnic_core_dev *dev,
				      int stride)
{
	u32 ring_size = MLX5_NODNIC_RING_ENTRIES * stride;
	u32 max_supported = 1U << dev->log_max_ring_size;

	return min(ring_size, max_supported);
}

static int mlx5_nodnic_write_ring_size(struct mlx5_nodnic_core_dev *dev,
				       int offset, int size)
{
	__be32 addr_l;
	int err;

	err = mlx5_nodnic_vsc_cfg_read_be32(dev->vsc_ctx, offset, &addr_l);
	if (err) {
		mlx5_nodnic_core_err(dev, "failed to read ring size: %d\n",
				     err);
		return err;
	}

	MLX5_SET(nodnic_q_addr_l, &addr_l, log_size, ilog2(size));

	err = mlx5_nodnic_vsc_cfg_write_be32(dev->vsc_ctx, offset, addr_l);
	if (err)
		mlx5_nodnic_core_err(dev, "failed to write ring size: %d\n",
				     err);
	return err;
}

static int mlx5_nodnic_read_qn(struct mlx5_nodnic_core_dev *dev,
			       struct mlx5_nodnic_ring *ring, u32 offset)
{
	__be32 qn_dword;
	int err;

	err = mlx5_nodnic_vsc_cfg_read_be32(dev->vsc_ctx, offset, &qn_dword);
	if (err) {
		mlx5_nodnic_core_err(dev, "failed to read queue number: %d\n",
				     err);
		return err;
	}

	ring->qn = MLX5_GET(nodnic_ring_q_number, &qn_dword, queue_number);

	return 0;
}

static int mlx5_nodnic_write_ring_dbr_addr(struct mlx5_nodnic_core_dev *dev,
					   u32 ring_offset)
{
	int off_h = ring_offset + MLX5_NODNIC_RING_DBR_ADDR_H;
	int off_l = ring_offset + MLX5_NODNIC_RING_DBR_ADDR_L;
	struct mlx5_nodnic_dbr *dbr = &dev->priv->dbr;
	__be32 dbr_h, dbr_l;
	int err;

	dbr_l = 0;
	MLX5_SET(nodnic_ring_dbr_addr_l, &dbr_l, db_record_addr_l,
		 (u32)(dbr->dma_handle >> 2));
	err = mlx5_nodnic_vsc_cfg_write_be32(dev->vsc_ctx, off_l, dbr_l);
	if (err) {
		mlx5_nodnic_core_err(dev,
				     "failed to write ring DBR addr low: %d\n",
				     err);
		return err;
	}

	dbr_h = cpu_to_be32(upper_32_bits(dbr->dma_handle));
	err = mlx5_nodnic_vsc_cfg_write_be32(dev->vsc_ctx, off_h, dbr_h);
	if (err) {
		mlx5_nodnic_core_err(dev,
				     "failed to write ring DBR addr high: %d\n",
				     err);
		return err;
	}

	return 0;
}

static int mlx5_nodnic_alloc_ring(struct mlx5_nodnic_core_dev *dev,
				  struct mlx5_nodnic_ring *ring, int size)
{
	dma_addr_t dma_handle;
	void *buf;

	buf = dma_alloc_coherent(dev->device, size, &dma_handle, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	*ring = (struct mlx5_nodnic_ring) {
		.wq		= buf,
		.dma_handle	= dma_handle,
		.size		= size,
	};

	return 0;
}

static void mlx5_nodnic_free_ring(struct mlx5_nodnic_core_dev *dev,
				  struct mlx5_nodnic_ring *ring)
{
	dma_free_coherent(dev->device, ring->size, ring->wq,
			  ring->dma_handle);
	memset(ring, 0, sizeof(*ring));
}

static int mlx5_nodnic_init_ring(struct mlx5_nodnic_core_dev *dev,
				 struct mlx5_nodnic_ring *ring, u32 ring_offset,
				 int stride)
{
	int ring_addr_h = ring_offset + MLX5_NODNIC_RING_ADDR_H;
	int ring_addr_l = ring_offset + MLX5_NODNIC_RING_ADDR_L;
	int size, err;

	size = mlx5_nodnic_calc_ring_size(dev, stride);

	err = mlx5_nodnic_alloc_ring(dev, ring, size);
	if (err)
		return err;

	err = mlx5_nodnic_write_ring_addr(dev, ring->dma_handle, ring_addr_h,
					  ring_addr_l);
	if (err)
		goto err_ring_free;

	err = mlx5_nodnic_write_ring_size(dev, ring_addr_l, size);
	if (err)
		goto err_ring_free;

	ring->num_entries = size / stride;

	err = mlx5_nodnic_read_qn(dev, ring,
				  ring_offset + MLX5_NODNIC_RING_QUEUE_NUMBER);
	if (err)
		goto err_ring_free;

	err = mlx5_nodnic_write_ring_dbr_addr(dev, ring_offset);
	if (err)
		goto err_ring_free;

	return 0;

err_ring_free:
	mlx5_nodnic_free_ring(dev, ring);
	return err;
}

static int mlx5_nodnic_alloc_dbr(struct mlx5_nodnic_core_dev *dev,
				 struct mlx5_nodnic_dbr *dbr)
{
	const u32 bytes = MLX5_NODNIC_DBR_WORDS * sizeof(__be32);
	dma_addr_t dma_handle;
	void *buf;

	buf = dma_alloc_coherent(dev->device, bytes, &dma_handle, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	*dbr = (struct mlx5_nodnic_dbr) {
		.db		= (__be32 *)buf,
		.alloc_size	= bytes,
		.dma_handle	= dma_handle,
	};

	return 0;
}

static void mlx5_nodnic_free_dbr(struct mlx5_nodnic_core_dev *dev,
				 struct mlx5_nodnic_dbr *dbr)
{
	if (!dbr->db)
		return;

	dma_free_coherent(dev->device, dbr->alloc_size, dbr->db,
			  dbr->dma_handle);
}

static int mlx5_nodnic_init_cq_dbr(struct mlx5_nodnic_core_dev *dev)
{
	struct mlx5_nodnic_dbr *dbr = &dev->priv->cq.dbr;
	__be32 dbr_h, dbr_l;
	int err;

	err = mlx5_nodnic_alloc_dbr(dev, dbr);
	if (err)
		return err;

	dbr_l = cpu_to_be32(lower_32_bits(dbr->dma_handle));
	err = mlx5_nodnic_vsc_cfg_write_be32(dev->vsc_ctx,
					     MLX5_NODNIC_CQ_DBR_ADDR_L,
					     dbr_l);
	if (err) {
		mlx5_nodnic_core_err(dev,
				     "failed to write CQ DBR addr low: %d\n",
				     err);
		goto err_free_dbr;
	}

	dbr_h = cpu_to_be32(upper_32_bits(dbr->dma_handle));
	err = mlx5_nodnic_vsc_cfg_write_be32(dev->vsc_ctx,
					     MLX5_NODNIC_CQ_DBR_ADDR_H,
					     dbr_h);
	if (err) {
		mlx5_nodnic_core_err(dev,
				     "failed to write CQ DBR addr high: %d\n",
				     err);
		goto err_free_dbr;
	}

	dev->priv->cq.dbr.db[1] = MLX5_NODNIC_CQ_INIT_CMD_SN;

	return 0;

err_free_dbr:
	mlx5_nodnic_free_dbr(dev, &dev->priv->cq.dbr);
	return err;
}

static void mlx5_nodnic_cleanup_cq_dbr(struct mlx5_nodnic_core_dev *dev)
{
	mlx5_nodnic_free_dbr(dev,  &dev->priv->cq.dbr);
}

/* log_cq_size should be read after rq and sq ring sizes were set. */
static int mlx5_nodnic_read_cq_ring_size(struct mlx5_nodnic_core_dev *dev)
{
	struct mlx5_nodnic_cq *cq = &dev->priv->cq;
	__be32 cq_addr_l;
	u32 log_cq_size;
	int err;

	err = mlx5_nodnic_vsc_cfg_read_be32(dev->vsc_ctx,
					    MLX5_NODNIC_PORT_CQ_ADDR_L,
					    &cq_addr_l);
	if (err) {
		mlx5_nodnic_core_err(dev, "failed to read CQ ring size: %d\n",
				     err);
		return err;
	}

	log_cq_size = MLX5_GET(nodnic_q_addr_l, &cq_addr_l, log_size);
	cq->num_entries = 1ULL << log_cq_size;
	cq->log_num_entries = log_cq_size;

	return 0;
}

static int mlx5_nodnic_init_cq_ring(struct mlx5_nodnic_core_dev *dev)
{
	struct mlx5_nodnic_cq *cq = &dev->priv->cq;
	struct mlx5_nodnic_ring *ring;
	int err;

	ring = &cq->ring;

	err = mlx5_nodnic_read_cq_ring_size(dev);
	if (err)
		return err;

	err = mlx5_nodnic_alloc_ring(dev, ring,
				     cq->num_entries * MLX5_NODNIC_CQE_SIZE_B);
	if (err)
		return err;

	err = mlx5_nodnic_write_ring_addr(dev, ring->dma_handle,
					  MLX5_NODNIC_PORT_CQ_ADDR_H,
					  MLX5_NODNIC_PORT_CQ_ADDR_L);
	if (err)
		goto err_free_cq;

	return 0;

err_free_cq:
	mlx5_nodnic_free_ring(dev, &cq->ring);
	return err;
}

static void mlx5_nodnic_cleanup_cq_ring(struct mlx5_nodnic_core_dev *dev)
{
	return mlx5_nodnic_free_ring(dev, &dev->priv->cq.ring);
}

static int mlx5_nodnic_read_cq_n(struct mlx5_nodnic_core_dev *dev)
{
	__be32 cq_n;
	int err;

	err = mlx5_nodnic_vsc_cfg_read_be32(dev->vsc_ctx, MLX5_NODNIC_CQ_N,
					    &cq_n);
	if (err) {
		mlx5_nodnic_core_err(dev, "failed to read CQ number: %d\n",
				     err);
		return err;
	}

	dev->priv->cq.cqn = MLX5_GET(nodnic_cqn, &cq_n, cq_n);

	return 0;
}

static irqreturn_t mlx5_nodnic_cq_irq_handler(int irq, void *data)
{
	struct mlx5_nodnic_cq *cq = data;

	cq->arm_sn++;
	napi_schedule_irqoff(&cq->napi);

	return IRQ_HANDLED;
}

static int mlx5_nodnic_setup_data_irq(struct mlx5_nodnic_cq *cq)
{
	struct mlx5_nodnic_priv *priv = container_of(cq,
						     struct mlx5_nodnic_priv,
						     cq);
	struct net_device *netdev = priv->netdev;
	int irqn, err;

	irqn = pci_irq_vector(priv->core_dev->pdev, MLX5_NODNIC_DATA_MSIX);
	if (irqn < 0) {
		netdev_err(netdev, "pci_irq_vector failed: %d\n", irqn);
		return irqn;
	}

	err = request_irq(irqn, mlx5_nodnic_cq_irq_handler, 0,
			  "mlx5_nodnic-cq", cq);
	if (err) {
		netdev_err(netdev, "request_irq failed\n");
		return err;
	}
	cq->irqn = irqn;

	return 0;
}

static void mlx5_nodnic_cleanup_data_irq(struct mlx5_nodnic_cq *cq)
{
	free_irq(cq->irqn, cq);
}

int mlx5_nodnic_init_working_buffer(struct mlx5_nodnic_core_dev *dev)
{
	struct mlx5_nodnic_ring *work_buf = &dev->priv->working_buffer;
	u32 size = 1U << dev->log_working_buffer_size;
	int err;

	err = mlx5_nodnic_alloc_ring(dev, work_buf, size);
	if (err)
		return err;

	err = mlx5_nodnic_write_ring_addr(dev, work_buf->dma_handle,
					  MLX5_NODNIC_PORT_WORK_BUF_ADDR_H,
					  MLX5_NODNIC_PORT_WORK_BUF_ADDR_L);
	if (err)
		goto err_free_working_buffer;

	return 0;

err_free_working_buffer:
	mlx5_nodnic_free_ring(dev, work_buf);
	return err;
}

int mlx5_nodnic_open_cq(struct mlx5_nodnic_core_dev *dev)
{
	struct mlx5_nodnic_cq *cq = &dev->priv->cq;
	int err;

	cq->cc = 0;
	cq->arm_sn = 0;

	err = mlx5_nodnic_init_cq_ring(dev);
	if (err)
		return err;

	err = mlx5_nodnic_init_cq_dbr(dev);
	if (err)
		goto err_cleanup_ring;

	err = mlx5_nodnic_read_cq_n(dev);
	if (err)
		goto err_cleanup_dbr;

	netif_napi_add_config_locked(dev->priv->netdev, &cq->napi,
				     mlx5_nodnic_napi_poll, 0);

	err = mlx5_nodnic_setup_data_irq(cq);
	if (err)
		goto err_napi_del;

	netif_napi_set_irq_locked(&cq->napi, cq->irqn);

	return 0;

err_napi_del:
	netif_napi_del_locked(&cq->napi);
err_cleanup_dbr:
	mlx5_nodnic_cleanup_cq_dbr(dev);
err_cleanup_ring:
	mlx5_nodnic_cleanup_cq_ring(dev);
	return err;
}

static void mlx5_nodnic_close_cq(struct mlx5_nodnic_cq *cq)
{
	struct mlx5_nodnic_core_dev *dev =
		container_of(cq, struct mlx5_nodnic_priv, cq)->core_dev;

	mlx5_nodnic_cleanup_data_irq(cq);
	netif_napi_del_locked(&cq->napi);
	mlx5_nodnic_cleanup_cq_dbr(dev);
	mlx5_nodnic_cleanup_cq_ring(dev);
}

int mlx5_nodnic_open_sq(struct mlx5_nodnic_core_dev *dev)
{
	struct mlx5_nodnic_priv *priv = dev->priv;
	struct mlx5_nodnic_sq *sq = &priv->sq;
	struct mlx5_nodnic_ring *ring;
	int err;

	sq->netdev = priv->netdev;
	sq->device = dev->device;
	sq->pc = 0;
	sq->cc = 0;
	ring = &sq->ring;

	err = mlx5_nodnic_init_ring(dev, ring, MLX5_NODNIC_SEND_RING_OFFSET,
				    MLX5_NODNIC_SQ_WQEBB_B);
	if (err)
		return err;

	ring->lkey = dev->lkey;

	sq->wqe_info = kvcalloc(ring->num_entries,
				sizeof(struct mlx5_nodnic_tx_wqe_info),
				GFP_KERNEL);
	if (!sq->wqe_info) {
		err = -ENOMEM;
		goto err_free_ring;
	}

	return 0;

err_free_ring:
	mlx5_nodnic_free_ring(dev, ring);
	return err;
}

static void mlx5_nodnic_close_sq(struct mlx5_nodnic_core_dev *dev)
{
	struct mlx5_nodnic_sq *sq = &dev->priv->sq;

	mlx5_nodnic_sq_free_pending(sq);
	mlx5_nodnic_free_ring(dev, &sq->ring);
	kvfree(sq->wqe_info);
}

int mlx5_nodnic_open_rq(struct mlx5_nodnic_core_dev *dev)
{
	struct mlx5_nodnic_rq *rq = &dev->priv->rq;
	struct mlx5_nodnic_ring *ring;
	int err;

	rq->pc = 0;
	rq->cc = 0;
	ring = &rq->ring;

	err = mlx5_nodnic_init_ring(dev, ring, MLX5_NODNIC_RECEIVE_RING_OFFSET,
				    MLX5_NODNIC_RQ_STRIDE_BYTES);
	if (err)
		return err;

	ring->lkey = dev->lkey;

	return 0;
}

static void mlx5_nodnic_close_rq(struct mlx5_nodnic_core_dev *dev)
{
	struct mlx5_nodnic_rq *rq = &dev->priv->rq;

	mlx5_nodnic_free_ring(dev, &rq->ring);
}

static int mlx5_nodnic_open_queues(struct mlx5_nodnic_core_dev *dev)
{
	struct mlx5_nodnic_vsc_ctx *vsc_ctx = dev->vsc_ctx;
	int err;

	/* one doorbell record shared by both SQ and RQ */
	err = mlx5_nodnic_alloc_dbr(dev, &dev->priv->dbr);
	if (err)
		return err;

	err = mlx5_nodnic_vsc_context_acquire(vsc_ctx);
	if (err)
		goto err_free_dbr;

	err = mlx5_nodnic_open_sq(dev);
	if (err)
		goto err_release_vsc;

	err = mlx5_nodnic_open_rq(dev);
	if (err)
		goto err_close_sq;

	err = mlx5_nodnic_open_cq(dev);
	if (err)
		goto err_close_rq;

	err = mlx5_nodnic_init_working_buffer(dev);
	if (err)
		goto err_close_cq;

	mlx5_nodnic_vsc_context_release(vsc_ctx);

	return 0;

err_close_cq:
	mlx5_nodnic_close_cq(&dev->priv->cq);
err_close_rq:
	mlx5_nodnic_close_rq(dev);
err_close_sq:
	mlx5_nodnic_close_sq(dev);
err_release_vsc:
	mlx5_nodnic_vsc_context_release(vsc_ctx);
err_free_dbr:
	mlx5_nodnic_free_dbr(dev, &dev->priv->dbr);

	return err;
}

static void mlx5_nodnic_close_queues(struct mlx5_nodnic_core_dev *dev)
{
	struct mlx5_nodnic_priv *priv = dev->priv;

	mlx5_nodnic_free_ring(dev, &priv->working_buffer);
	mlx5_nodnic_close_cq(&priv->cq);
	mlx5_nodnic_close_rq(dev);
	mlx5_nodnic_close_sq(dev);
	mlx5_nodnic_free_dbr(dev, &priv->dbr);
}

static void mlx5_nodnic_update_carrier(struct mlx5_nodnic_priv *priv,
				       __be32 event)
{
	u32 port_state = MLX5_GET(nodnic_port_event, &event, port_state);
	bool up = port_state == MLX5_NODNIC_PORT_STATE_ACTIVE;

	/* Force re-notification if state is unchanged */
	if (up == netif_carrier_ok(priv->netdev)) {
		netif_carrier_event(priv->netdev);
		return;
	}
	if (up) {
		netif_carrier_on(priv->netdev);
		netdev_info(priv->netdev, "Link up\n");
	} else {
		netif_carrier_off(priv->netdev);
		netdev_info(priv->netdev, "Link down\n");
	}
}

static int mlx5_nodnic_refresh_carrier_locked(struct mlx5_nodnic_priv *priv)
{
	struct mlx5_nodnic_core_dev *dev = priv->core_dev;
	struct mlx5_nodnic_vsc_ctx *vsc_ctx;
	__be32 event;
	int err;

	vsc_ctx = dev->vsc_ctx;
	err = mlx5_nodnic_vsc_context_acquire(vsc_ctx);
	if (err)
		return err;

	err = mlx5_nodnic_vsc_cfg_read_be32(vsc_ctx, MLX5_NODNIC_PORT_EVENT,
					    &event);
	mlx5_nodnic_vsc_context_release(vsc_ctx);

	if (!err)
		mlx5_nodnic_update_carrier(priv, event);

	return err;
}

void mlx5_nodnic_refresh_carrier(struct mlx5_nodnic_priv *priv)
{
	mutex_lock(&priv->state_lock);
	if (test_bit(MLX5_NODNIC_STATE_OPENED, &priv->state))
		mlx5_nodnic_refresh_carrier_locked(priv);
	mutex_unlock(&priv->state_lock);
}

static int mlx5_nodnic_activate_rq(struct mlx5_nodnic_core_dev *dev)
{
	struct mlx5_nodnic_priv *priv = dev->priv;
	struct net_device *netdev = priv->netdev;
	struct mlx5_nodnic_rq *rq = &priv->rq;
	struct page_pool_params pp_params = {
		.flags    = PP_FLAG_DMA_MAP | PP_FLAG_DMA_SYNC_DEV,
		.order    = 0,
		.pool_size = rq->ring.num_entries,
		.nid      = dev_to_node(dev->device),
		.dev      = dev->device,
		.napi     = &priv->cq.napi,
		.netdev   = netdev,
		.dma_dir  = DMA_FROM_DEVICE,
		.offset   = MLX5_NODNIC_SKB_HEADROOM_BYTES,
		.max_len  = MLX5_NODNIC_HW_MTU,
	};
	int err;

	rq->page_pool = page_pool_create(&pp_params);
	if (IS_ERR(rq->page_pool)) {
		err = PTR_ERR(rq->page_pool);
		return err;
	}

	err = mlx5_nodnic_rq_alloc_pages(rq);
	if (err) {
		netdev_err(netdev, "failed to alloc RX pages, err=%d\n", err);
		goto err_destroy_page_pool;
	}

	netif_queue_set_napi(netdev, 0, NETDEV_QUEUE_TYPE_RX, &priv->cq.napi);

	return 0;

err_destroy_page_pool:
	page_pool_destroy(rq->page_pool);

	return err;
}

static void mlx5_nodnic_deactivate_rq(struct mlx5_nodnic_core_dev *dev)
{
	struct net_device *netdev = dev->priv->netdev;
	struct mlx5_nodnic_rq *rq = &dev->priv->rq;

	netif_queue_set_napi(netdev, 0, NETDEV_QUEUE_TYPE_RX, NULL);

	mlx5_nodnic_rq_free_pages(rq);
	page_pool_destroy(rq->page_pool);
}

static void mlx5_nodnic_tx_disable_queue(struct netdev_queue *txq)
{
	__netif_tx_lock_bh(txq);
	netif_tx_stop_queue(txq);
	__netif_tx_unlock_bh(txq);
}

static void mlx5_nodnic_activate_sq(struct mlx5_nodnic_core_dev *dev)
{
	struct mlx5_nodnic_priv *priv = dev->priv;
	struct mlx5_nodnic_sq *sq = &priv->sq;

	sq->txq = netdev_get_tx_queue(priv->netdev, 0);
	netdev_tx_reset_queue(sq->txq);
	netif_tx_start_queue(sq->txq);
	netif_queue_set_napi(sq->netdev, 0, NETDEV_QUEUE_TYPE_TX,
			     &priv->cq.napi);
}

static void mlx5_nodnic_deactivate_sq(struct mlx5_nodnic_sq *sq)
{
	netif_queue_set_napi(sq->netdev, 0, NETDEV_QUEUE_TYPE_TX, NULL);
	mlx5_nodnic_tx_disable_queue(sq->txq);
}

static void mlx5_nodnic_init_cqes_ownership(struct mlx5_nodnic_cq *cq)
{
	struct mlx5_cqe64 *cqe;

	for (int i = 0; i < cq->num_entries; i++) {
		cqe = (struct mlx5_cqe64 *)
		      ((u8 *)cq->ring.wq + i * MLX5_NODNIC_CQE_SIZE_B);
		cqe->op_own = 0xf1;
	}
}

static int mlx5_nodnic_activate_queues(struct mlx5_nodnic_core_dev *dev)
{
	struct mlx5_nodnic_cq *cq = &dev->priv->cq;
	int err;

	napi_enable_locked(&cq->napi);

	mlx5_nodnic_init_cqes_ownership(cq);

	err = mlx5_nodnic_activate_rq(dev);
	if (err)
		goto err_napi;

	err = mlx5_nodnic_vsc_context_acquire(dev->vsc_ctx);
	if (err)
		goto err_rq;

	err = mlx5_nodnic_enable_port(dev);
	mlx5_nodnic_vsc_context_release(dev->vsc_ctx);
	if (err)
		goto err_rq;

	mlx5_nodnic_arm_cq(cq);
	napi_schedule(&cq->napi);

	mlx5_nodnic_activate_sq(dev);

	return 0;

err_rq:
	mlx5_nodnic_deactivate_rq(dev);
err_napi:
	napi_disable_locked(&cq->napi);

	return err;
}

static void mlx5_nodnic_deactivate_queues(struct mlx5_nodnic_core_dev *dev)
{
	if (!mlx5_nodnic_vsc_context_acquire(dev->vsc_ctx)) {
		mlx5_nodnic_disable_port(dev);
		mlx5_nodnic_vsc_context_release(dev->vsc_ctx);
	}

	mlx5_nodnic_deactivate_sq(&dev->priv->sq);
	napi_disable_locked(&dev->priv->cq.napi);
	mlx5_nodnic_deactivate_rq(dev);
}

int mlx5_nodnic_enable_port(struct mlx5_nodnic_core_dev *dev)
{
	struct mlx5_nodnic_vsc_ctx *vsc_ctx = dev->vsc_ctx;
	__be32 val = 0;
	int err;

	/* data_msix_en, event_msix_en must be set before activating port */
	MLX5_SET(nodnic_port_network, &val, data_msix_en, 1);
	MLX5_SET(nodnic_port_network, &val, event_msix_en, 1);
	err = mlx5_nodnic_vsc_cfg_write_be32(vsc_ctx, MLX5_NODNIC_PORT_NETWORK,
					     val);
	if (err) {
		mlx5_nodnic_core_err(dev,
				     "failed to write port network (msix): %d\n",
				     err);
		return err;
	}

	MLX5_SET(nodnic_port_network, &val, network_en, 1);
	MLX5_SET(nodnic_port_network, &val, receive_filter_en, BIT(0));

	err = mlx5_nodnic_vsc_cfg_write_be32(vsc_ctx, MLX5_NODNIC_PORT_NETWORK,
					     val);
	if (err) {
		mlx5_nodnic_core_err(dev,
				     "failed to write port network (enable): %d\n",
				     err);
		return err;
	}

	/* dma enabling requires a separate write */
	MLX5_SET(nodnic_port_network, &val, dma_en, 1);

	err = mlx5_nodnic_vsc_cfg_write_be32(vsc_ctx, MLX5_NODNIC_PORT_NETWORK,
					     val);
	if (err)
		mlx5_nodnic_core_err(dev,
				     "failed to write port network (dma): %d\n",
				     err);
	return err;
}

void mlx5_nodnic_disable_port(struct mlx5_nodnic_core_dev *dev)
{
	struct mlx5_nodnic_vsc_ctx *vsc_ctx = dev->vsc_ctx;
	__be32 val;
	int err;

	err = mlx5_nodnic_vsc_cfg_read_be32(vsc_ctx, MLX5_NODNIC_PORT_NETWORK,
					    &val);
	if (err)
		goto out;

	MLX5_SET(nodnic_port_network, &val, dma_en, 0);
	MLX5_SET(nodnic_port_network, &val, network_en, 0);
	err = mlx5_nodnic_vsc_cfg_write_be32(vsc_ctx, MLX5_NODNIC_PORT_NETWORK,
					     val);
	if (err)
		goto out;

	/* data_msix_en, event_msix_en can't be modified while port is active */
	MLX5_SET(nodnic_port_network, &val, data_msix_en, 0);
	MLX5_SET(nodnic_port_network, &val, event_msix_en, 0);
	err = mlx5_nodnic_vsc_cfg_write_be32(vsc_ctx, MLX5_NODNIC_PORT_NETWORK,
					     val);

out:
	if (err)
		mlx5_nodnic_core_warn(dev,
				      "failed to read/write to vsc err %d\n",
				      err);
}

static int mlx5_nodnic_init_uar_map(struct mlx5_nodnic_core_dev *dev)
{
	void __iomem *base;
	phys_addr_t paddr;
	u32 uar_page_size;

	uar_page_size = 1 << dev->log_uar_page_size;

	paddr = dev->bar_addr + (dev->send_ring0_uar_index * uar_page_size);

	base = ioremap(paddr, uar_page_size);
	if (!base) {
		mlx5_nodnic_core_err(dev, "failed to map UAR\n");
		return -ENOMEM;
	}

	dev->uar_base = base;

	return 0;
}

static void mlx5_nodnic_cleanup_uar_map(struct mlx5_nodnic_core_dev *dev)
{
	if (!dev->uar_base)
		return;

	iounmap(dev->uar_base);
	dev->uar_base = NULL;
}

static int mlx5_nodnic_open_locked(struct net_device *netdev)
{
	struct mlx5_nodnic_priv *priv = netdev_priv(netdev);
	struct mlx5_nodnic_core_dev *dev = priv->core_dev;
	int err;

	err = mlx5_nodnic_init_uar_map(dev);
	if (err)
		return err;

	err = mlx5_nodnic_open_queues(dev);
	if (err)
		goto err_uar;

	set_bit(MLX5_NODNIC_STATE_OPENED, &priv->state);

	err = mlx5_nodnic_activate_queues(dev);
	if (err)
		goto err_close;

	err = mlx5_nodnic_refresh_carrier_locked(dev->priv);
	if (err)
		netdev_err(dev->priv->netdev,
			   "failed to query carrier, err=%d\n", err);

	return 0;

err_close:
	clear_bit(MLX5_NODNIC_STATE_OPENED, &priv->state);
	mlx5_nodnic_close_queues(dev);
err_uar:
	mlx5_nodnic_cleanup_uar_map(dev);
	return err;
}

int mlx5_nodnic_open(struct net_device *netdev)
{
	struct mlx5_nodnic_priv *priv = netdev_priv(netdev);
	int err;

	mutex_lock(&priv->state_lock);
	err = mlx5_nodnic_open_locked(netdev);
	mutex_unlock(&priv->state_lock);

	return err;
}

static int mlx5_nodnic_close_locked(struct net_device *netdev)
{
	struct mlx5_nodnic_priv *priv = netdev_priv(netdev);
	struct mlx5_nodnic_core_dev *dev = priv->core_dev;

	mlx5_nodnic_deactivate_queues(dev);
	clear_bit(MLX5_NODNIC_STATE_OPENED, &priv->state);
	netif_carrier_off(priv->netdev);
	netdev_info(priv->netdev, "Link down\n");
	mlx5_nodnic_close_queues(dev);

	return 0;
}

int mlx5_nodnic_close(struct net_device *netdev)
{
	struct mlx5_nodnic_priv *priv = netdev_priv(netdev);
	int err = 0;

	mutex_lock(&priv->state_lock);
	if (!test_bit(MLX5_NODNIC_STATE_OPENED, &priv->state)) {
		mutex_unlock(&priv->state_lock);
		return 0;
	}

	err = mlx5_nodnic_close_locked(netdev);
	mutex_unlock(&priv->state_lock);

	mlx5_nodnic_cleanup_uar_map(priv->core_dev);

	return err;
}

static void mlx5_nodnic_update_sq_stats(const struct mlx5_nodnic_sq_stats *sq,
					struct rtnl_link_stats64 *s)
{
	s->tx_packets = sq->packets;
	s->tx_bytes = sq->bytes;
	s->tx_dropped = sq->dropped;
}

static void mlx5_nodnic_update_rq_stats(const struct mlx5_nodnic_rq_stats *rq,
					struct rtnl_link_stats64 *s)
{
	s->rx_packets = rq->packets;
	s->rx_bytes = rq->bytes;
}

static void mlx5_nodnic_get_stats64(struct net_device *netdev,
				    struct rtnl_link_stats64 *stats)
{
	struct mlx5_nodnic_priv *priv = netdev_priv(netdev);

	mlx5_nodnic_update_sq_stats(&priv->sq_stats, stats);
	mlx5_nodnic_update_rq_stats(&priv->rq_stats, stats);
}

static const struct net_device_ops mlx5_nodnic_netdev_ops = {
	.ndo_open		= mlx5_nodnic_open,
	.ndo_stop		= mlx5_nodnic_close,
	.ndo_start_xmit		= mlx5_nodnic_xmit,
	.ndo_get_stats64	= mlx5_nodnic_get_stats64,
	.ndo_features_check	= mlx5_nodnic_check_features,
};

void mlx5_nodnic_build_netdev(struct net_device *netdev)
{
	struct mlx5_nodnic_priv *priv = netdev_priv(netdev);
	struct mlx5_nodnic_core_dev *core_dev;

	core_dev = priv->core_dev;

	SET_NETDEV_DEV(netdev, core_dev->device);

	netdev->netdev_ops = &mlx5_nodnic_netdev_ops;
	netdev->request_ops_lock = true;

	netdev->hw_features = NETIF_F_HW_CSUM | NETIF_F_RXCSUM;
	netdev->features = netdev->hw_features;

	eth_hw_addr_set(netdev, core_dev->mac_address);
}

static void mlx5_nodnic_init_priv(struct mlx5_nodnic_priv *priv,
				  struct net_device *netdev,
				  struct mlx5_nodnic_core_dev *core_dev)
{
	priv->netdev = netdev;
	priv->core_dev = core_dev;
	mutex_init(&priv->state_lock);
}

static void mlx5_nodnic_cleanup_priv(struct mlx5_nodnic_priv *priv)
{
	mutex_destroy(&priv->state_lock);
}

struct net_device *mlx5_nodnic_create_netdev(struct mlx5_nodnic_core_dev *dev)
{
	struct mlx5_nodnic_priv *priv;
	struct net_device *netdev;

	netdev = alloc_etherdev_mqs(sizeof(struct mlx5_nodnic_priv), 1, 1);
	if (!netdev)
		return NULL;

	priv = netdev_priv(netdev);
	mlx5_nodnic_init_priv(priv, netdev, dev);
	dev->priv = priv;

	netif_carrier_off(netdev);
	netif_tx_disable(netdev);
	dev_net_set(netdev, &init_net);

	return netdev;
}

void mlx5_nodnic_cleanup_netdev(struct mlx5_nodnic_core_dev *dev)
{
	struct mlx5_nodnic_priv *priv;
	struct net_device *netdev;

	if (!dev->priv)
		return;

	priv = dev->priv;
	netdev = priv->netdev;
	if (!netdev)
		return;

	if (dev->netdev_registered) {
		netif_device_detach(netdev);
		unregister_netdev(netdev);
		dev->netdev_registered = false;
	}

	mlx5_nodnic_cleanup_priv(priv);
	dev->priv = NULL;

	free_netdev(netdev);
}
