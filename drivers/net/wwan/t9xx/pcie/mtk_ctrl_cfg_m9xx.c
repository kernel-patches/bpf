// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022, MediaTek Inc.
 */

#include "mtk_cldma.h"
#include "mtk_trans_ctrl.h"

#define TRB_SRV_NUM	(1)

static const int mtk_srv_cfg_m9xx[NR_CLDMA][HW_QUE_NUM] = {
	{0},
	{0},
};

/* the number of RX GPDs should be at least two */
static const struct queue_info mtk_queue_info_m9xx[] = {
	{CCCI_CONTROL_TX, CCCI_CONTROL_RX, CLDMA1, TXQ(0), RXQ(0),
	 Q_MTU_3_5K, Q_MTU_3_5K, TX_GPD_NUM, RX_GPD_NUM, Q_FRAG_3_5K, Q_FRAG_3_5K, 0},
	{CCCI_SAP_CONTROL_TX, CCCI_SAP_CONTROL_RX, CLDMA0, TXQ(0), RXQ(0),
	 Q_MTU_3_5K, Q_MTU_3_5K, TX_GPD_NUM, RX_GPD_NUM, Q_FRAG_3_5K, Q_FRAG_3_5K, 0},
};

struct mtk_ctrl_info mtk_ctrl_info_m9xx = {
	.queue_info = (struct queue_info *)mtk_queue_info_m9xx,
	.queue_info_num = ARRAY_SIZE(mtk_queue_info_m9xx),
	.srv_cfg = mtk_srv_cfg_m9xx,
	.trb_srv_num = TRB_SRV_NUM,
};
