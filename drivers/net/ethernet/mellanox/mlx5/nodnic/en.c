// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.

#include <linux/interrupt.h>
#include <linux/mlx5/cq.h>

#include "en.h"
#include "nodnic.h"
#include "rx.h"
#include "tx.h"

#define MLX5_NODNIC_TX_CQ_POLL_BUDGET        128

enum mlx5_nodnic_cqe_result {
	MLX5_NODNIC_CQE_TX,
	MLX5_NODNIC_CQE_RX,
	MLX5_NODNIC_CQE_IGNORED,
};

static const char *mlx5_nodnic_cqe_err_syndrome_str(u8 syndrome)
{
	switch (syndrome) {
	case MLX5_CQE_SYNDROME_LOCAL_LENGTH_ERR:
		return "LOCAL_LENGTH_ERR";
	case MLX5_CQE_SYNDROME_LOCAL_QP_OP_ERR:
		return "LOCAL_QP_OP_ERR";
	case MLX5_CQE_SYNDROME_LOCAL_PROT_ERR:
		return "LOCAL_PROT_ERR";
	case MLX5_CQE_SYNDROME_WR_FLUSH_ERR:
		return "WR_FLUSH_ERR";
	case MLX5_CQE_SYNDROME_MW_BIND_ERR:
		return "MW_BIND_ERR";
	case MLX5_CQE_SYNDROME_BAD_RESP_ERR:
		return "BAD_RESP_ERR";
	case MLX5_CQE_SYNDROME_LOCAL_ACCESS_ERR:
		return "LOCAL_ACCESS_ERR";
	case MLX5_CQE_SYNDROME_REMOTE_INVAL_REQ_ERR:
		return "REMOTE_INVAL_REQ_ERR";
	case MLX5_CQE_SYNDROME_REMOTE_ACCESS_ERR:
		return "REMOTE_ACCESS_ERR";
	case MLX5_CQE_SYNDROME_REMOTE_OP_ERR:
		return "REMOTE_OP_ERR";
	case MLX5_CQE_SYNDROME_TRANSPORT_RETRY_EXC_ERR:
		return "TRANSPORT_RETRY_EXC_ERR";
	case MLX5_CQE_SYNDROME_RNR_RETRY_EXC_ERR:
		return "RNR_RETRY_EXC_ERR";
	case MLX5_CQE_SYNDROME_REMOTE_ABORTED_ERR:
		return "REMOTE_ABORTED_ERR";
	default:
		return "UNKNOWN";
	}
}

static void mlx5_nodnic_handle_err_cqe(struct mlx5_nodnic_cq *cq,
				       struct mlx5_cqe64 *cqe64,
				       int napi_budget)
{
	struct mlx5_nodnic_priv *priv = container_of(cq,
						     struct mlx5_nodnic_priv,
						     cq);
	struct mlx5_err_cqe *err_cqe = (struct mlx5_err_cqe *)cqe64;
	u8 vendor_syndrome, syndrome;
	const char *queue_type;
	u16 wqe_counter;
	u8 opcode;

	opcode = err_cqe->op_own >> 4;
	syndrome = err_cqe->syndrome;
	vendor_syndrome = err_cqe->vendor_err_synd;
	wqe_counter = be16_to_cpu(err_cqe->wqe_counter);

	queue_type = (opcode == OPCODE_CQ_SEND_ERR) ? "SQ" : "RQ";

	netdev_err(priv->netdev,
		   "%s CQE error: syndrome=0x%02x (%s), vendor_syndrome=0x%02x, wqe_counter=%u, cq_ci=%d\n",
		   queue_type,
		   syndrome, mlx5_nodnic_cqe_err_syndrome_str(syndrome),
		   vendor_syndrome, wqe_counter, cq->cc);

	print_hex_dump(KERN_ERR, "mlx5_nodnic err CQE: ", DUMP_PREFIX_OFFSET,
		       16, 1, err_cqe, sizeof(*err_cqe), false);

	if (opcode == OPCODE_CQ_SEND_ERR) {
		struct mlx5_nodnic_sq *sq = &priv->sq;
		u16 sq_pi = mlx5_nodnic_sq_get_pi(sq, wqe_counter);

		mlx5_nodnic_complete_send_wqe(sq, &sq->wqe_info[sq_pi],
					      napi_budget);
	} else {
		struct mlx5_nodnic_rq *rq = &priv->rq;
		u16 ci = wqe_counter & (rq->ring.num_entries - 1);

		mlx5_nodnic_release_rx_wqe(rq, ci);
	}
}

static u32 mlx5_nodnic_cq_get_ci(struct mlx5_nodnic_cq *cq)
{
	return cq->cc & (cq->num_entries - 1);
}

static u8 mlx5_nodnic_cq_get_sw_ownership_val(struct mlx5_nodnic_cq *cq)
{
	return (cq->cc >> cq->log_num_entries) & 1;
}

static struct mlx5_cqe64 *mlx5_nodnic_cq_get_cqe(struct mlx5_nodnic_cq *cq)
{
	u8 cqe_ownership_bit, sw_ownership_val;
	struct mlx5_cqe64 *cqe;
	u32 ci;

	ci = mlx5_nodnic_cq_get_ci(cq);
	cqe = (struct mlx5_cqe64 *)cq->ring.wq + ci;

	cqe_ownership_bit = cqe->op_own & MLX5_NODNIC_CQE_OWNER_MASK;
	sw_ownership_val = mlx5_nodnic_cq_get_sw_ownership_val(cq);
	if (cqe_ownership_bit != sw_ownership_val)
		return NULL;

	/* ensure cqe content is read after cqe ownership bit */
	dma_rmb();

	return cqe;
}

static u8 mlx5_nodnic_cq_get_opcode(struct mlx5_cqe64 *cqe)
{
	return cqe->op_own >> 4;
}

static enum mlx5_nodnic_cqe_result
mlx5_nodnic_handle_cqe(struct mlx5_nodnic_cq *cq, struct mlx5_cqe64 *cqe,
		       int budget)
{
	struct net_device *netdev =
		container_of(cq, struct mlx5_nodnic_priv, cq)->netdev;
	u8 opcode = mlx5_nodnic_cq_get_opcode(cqe);
	enum mlx5_nodnic_cqe_result result;

	switch (opcode) {
	case OPCODE_CQ_SEND:
		mlx5_nodnic_handle_send_cqe(cq, cqe, budget);
		result = MLX5_NODNIC_CQE_TX;
		break;

	case OPCODE_CQ_RECV:
		mlx5_nodnic_handle_recv_cqe(cq, cqe);
		result = MLX5_NODNIC_CQE_RX;
		break;

	case OPCODE_CQ_SEND_ERR:
		mlx5_nodnic_handle_err_cqe(cq, cqe, budget);
		result = MLX5_NODNIC_CQE_TX;
		break;

	case OPCODE_CQ_RECV_ERR:
		mlx5_nodnic_handle_err_cqe(cq, cqe, budget);
		result = MLX5_NODNIC_CQE_RX;
		break;

	case OPCODE_CQ_INVALID:
		/* Invalid/stale CQE - silently consume it.
		 * This can occur after device restart when stale CQEs
		 * from the previous session are still in the hardware CQ.
		 */
		result = MLX5_NODNIC_CQE_IGNORED;
		break;

	default:
		netdev_err(netdev,
			   "unexpected CQE opcode 0x%02x at cq_ci=%d\n",
			   opcode, cq->cc);
		result = MLX5_NODNIC_CQE_IGNORED;
		break;
	}

	cq->cc++;
	return result;
}

void mlx5_nodnic_arm_cq(struct mlx5_nodnic_cq *cq)
{
	struct mlx5_nodnic_core_dev *dev =
		container_of(cq, struct mlx5_nodnic_priv, cq)->core_dev;
	__be32 doorbell[2];
	u32 sn, ci, val;

	sn = cq->arm_sn & 3;
	ci = cq->cc & 0xffffff;
	val = sn << 28 | MLX5_CQ_DB_REQ_NOT | ci;

	cq->dbr.db[0] = cpu_to_be32(ci);
	/* arm_db is the second dword of the CQ doorbell record */
	cq->dbr.db[1] = cpu_to_be32(val);

	/* Make sure that the doorbell record in host memory is
	 * written before ringing the doorbell via PCI MMIO.
	 */
	wmb();

	doorbell[0] = cpu_to_be32(val);
	doorbell[1] = cpu_to_be32(cq->cqn);

	mlx5_write64(doorbell, dev->uar_base + MLX5_CQ_DOORBELL);
}

int mlx5_nodnic_napi_poll(struct napi_struct *napi, int budget)
{
	struct mlx5_nodnic_cq *cq = container_of(napi,
						 struct mlx5_nodnic_cq, napi);
	struct mlx5_nodnic_priv *priv = container_of(cq,
						     struct mlx5_nodnic_priv,
						     cq);
	int tx_work_done = 0, rx_work_done = 0;
	enum mlx5_nodnic_cqe_result result;
	struct mlx5_cqe64 *cqe;

	while (true) {
		cqe = mlx5_nodnic_cq_get_cqe(cq);
		if (!cqe)
			break;

		result = mlx5_nodnic_handle_cqe(cq, cqe, budget);
		switch (result) {
		case MLX5_NODNIC_CQE_TX:
			if (++tx_work_done >= MLX5_NODNIC_TX_CQ_POLL_BUDGET)
				goto poll_done;
			break;
		case MLX5_NODNIC_CQE_RX:
			if (++rx_work_done >= budget)
				goto poll_done;
			break;
		case MLX5_NODNIC_CQE_IGNORED:
			break;
		}
	}

poll_done:
	if (!mlx5_nodnic_rq_post_wqes(priv))
		return budget;

	if (rx_work_done >= budget)
		return budget;

	if (napi_complete_done(napi, rx_work_done))
		mlx5_nodnic_arm_cq(cq);

	return rx_work_done;
}

netdev_features_t
mlx5_nodnic_check_features(struct sk_buff *skb, struct net_device *netdev,
			   netdev_features_t features)
{
	features = vlan_features_check(skb, features);

	/* Validate if the tunneled packet is being offloaded by HW */
	if (skb->encapsulation && (features & NETIF_F_CSUM_MASK))
		return features & ~NETIF_F_CSUM_MASK;

	return features;
}
