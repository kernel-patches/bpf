// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Nebula Matrix Limited.
 */
#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include "nbl_dispatch.h"

static int nbl_disp_chan_get_vsi_id_req(struct nbl_dispatch_mgt *disp_mgt,
					u16 type, u16 *vsi_id)
{
	struct nbl_channel_ops *chan_ops = disp_mgt->chan_ops_tbl->ops;
	struct nbl_common_info *common = disp_mgt->common;
	struct nbl_chan_param_get_vsi_id result = { 0 };
	struct nbl_chan_param_get_vsi_id param = { 0 };
	struct nbl_chan_send_info chan_send = {0};
	int ret;

	param.type = cpu_to_le16(type);

	nbl_chan_fill_send_info(&chan_send, common->mgt_pf,
				NBL_CHAN_MSG_GET_VSI_ID,
				&param, sizeof(param), &result,
				sizeof(result), 1);
	ret = chan_ops->send_msg(disp_mgt->chan_ops_tbl->priv, &chan_send);
	if (ret)
		return ret;
	if (chan_send.ack_len != sizeof(result)) {
		dev_err(disp_mgt->common->dev,
			"get_vsi_id: short ACK, ack_len=%u expected %zu\n",
			chan_send.ack_len, sizeof(result));
		return -EREMOTEIO;
	}
	*vsi_id = le16_to_cpu(result.vsi_id);
	return 0;
}

static void nbl_disp_chan_get_vsi_id_resp(void *priv, u16 src_id, u16 msg_id,
					  void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = disp_mgt->chan_ops_tbl->ops;
	struct nbl_resource_ops *res_ops = disp_mgt->res_ops_tbl->ops;
	struct nbl_resource_mgt *p = disp_mgt->res_ops_tbl->priv;
	struct device *dev = disp_mgt->common->dev;
	struct nbl_chan_param_get_vsi_id result = { 0 };
	struct nbl_chan_param_get_vsi_id param = { 0 };
	struct nbl_chan_ack_info chan_ack;
	int err = 0;
	u16 vsi_id = 0;
	u32 rel_pf_id;
	int ret;

	ret = nbl_common_func_id_to_rel_pf_id(disp_mgt->common, src_id,
					      &rel_pf_id);
	if (ret) {
		err = -EPERM;
		goto ack_out;
	}
	if (rel_pf_id >= disp_mgt->common->max_pf) {
		err = -EPERM;
		goto ack_out;
	}
	if (data_len < sizeof(param)) {
		err = -EREMOTEIO;
		goto ack_out;
	}
	memcpy(&param, data, sizeof(param));

	if (res_ops->get_vsi_id) {
		ret = res_ops->get_vsi_id(p, src_id, le16_to_cpu(param.type),
					  &vsi_id);
		if (ret)
			err = -EREMOTEIO;
	} else {
		err = -EOPNOTSUPP;
	}

	result.vsi_id = cpu_to_le16(vsi_id);
ack_out:
	nbl_chan_fill_ack_info(&chan_ack, src_id,
			       NBL_CHAN_MSG_GET_VSI_ID, msg_id, err,
			       &result, sizeof(result));
	ret = chan_ops->send_ack(disp_mgt->chan_ops_tbl->priv, &chan_ack);
	if (ret)
		dev_err(dev,
			"channel send ack failed with ret: %d, msg_type: %d\n",
			ret, NBL_CHAN_MSG_GET_VSI_ID);
}

static int nbl_disp_chan_get_eth_id_req(struct nbl_dispatch_mgt *disp_mgt,
					u16 vsi_id, u8 *eth_num, u8 *eth_id,
					u8 *logic_eth_id)
{
	struct nbl_channel_ops *chan_ops = disp_mgt->chan_ops_tbl->ops;
	struct nbl_common_info *common = disp_mgt->common;
	struct nbl_chan_param_get_eth_id result = { 0 };
	struct nbl_chan_param_get_eth_id param = { 0 };
	struct nbl_chan_send_info chan_send = {0};
	int ret;

	param.vsi_id = cpu_to_le16(vsi_id);

	nbl_chan_fill_send_info(&chan_send, common->mgt_pf,
				NBL_CHAN_MSG_GET_ETH_ID,
				&param, sizeof(param), &result,
				sizeof(result), 1);
	ret = chan_ops->send_msg(disp_mgt->chan_ops_tbl->priv, &chan_send);
	if (ret)
		return ret;
	if (chan_send.ack_len != sizeof(result)) {
		dev_err(disp_mgt->common->dev,
			"get_eth_id: short ACK, ack_len=%u expected %zu\n",
			chan_send.ack_len, sizeof(result));
		return -EREMOTEIO;
	}
	*eth_num = result.eth_num;
	*eth_id = result.eth_id;
	*logic_eth_id = result.logic_eth_id;

	return 0;
}

static void nbl_disp_chan_get_eth_id_resp(void *priv, u16 src_id, u16 msg_id,
					  void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = disp_mgt->chan_ops_tbl->ops;
	struct nbl_resource_ops *res_ops = disp_mgt->res_ops_tbl->ops;
	struct nbl_resource_mgt *p = disp_mgt->res_ops_tbl->priv;
	struct nbl_chan_param_get_eth_id result = { 0 };
	struct nbl_chan_param_get_eth_id param = { 0 };
	struct device *dev = disp_mgt->common->dev;
	struct nbl_chan_ack_info chan_ack;
	int err = 0;
	u32 rel_pf_id;
	int ret;

	ret = nbl_common_func_id_to_rel_pf_id(disp_mgt->common, src_id,
					      &rel_pf_id);
	if (ret) {
		err = -EPERM;
		goto ack_out;
	}
	if (rel_pf_id >= disp_mgt->common->max_pf) {
		err = -EPERM;
		goto ack_out;
	}
	if (data_len < sizeof(param)) {
		err = -EREMOTEIO;
		goto ack_out;
	}
	memcpy(&param, data, sizeof(param));

	if (res_ops->get_eth_id) {
		ret = res_ops->get_eth_id(p, src_id, le16_to_cpu(param.vsi_id),
					  &result.eth_num, &result.eth_id,
					  &result.logic_eth_id);
		if (ret)
			err = -EREMOTEIO;
	} else {
		err = -EOPNOTSUPP;
	}
ack_out:
	nbl_chan_fill_ack_info(&chan_ack, src_id,
			       NBL_CHAN_MSG_GET_ETH_ID, msg_id, err,
			       &result, sizeof(result));
	ret = chan_ops->send_ack(disp_mgt->chan_ops_tbl->priv, &chan_ack);
	if (ret)
		dev_err(dev,
			"channel send ack failed with ret: %d, msg_type: %d\n",
			ret, NBL_CHAN_MSG_GET_ETH_ID);
}

static void nbl_disp_deinit_module(struct nbl_dispatch_mgt *disp_mgt)
{
	struct nbl_resource_ops *res_ops = disp_mgt->res_ops_tbl->ops;
	struct nbl_resource_mgt *p = disp_mgt->res_ops_tbl->priv;

	if (res_ops->deinit_module)
		res_ops->deinit_module(p);
}

static int nbl_disp_init_module(struct nbl_dispatch_mgt *disp_mgt)
{
	struct nbl_resource_ops *res_ops = disp_mgt->res_ops_tbl->ops;
	struct nbl_resource_mgt *p = disp_mgt->res_ops_tbl->priv;

	if (res_ops->init_module)
		return res_ops->init_module(p);
	return -EOPNOTSUPP;
}

static int nbl_disp_cfg_msix_map(struct nbl_dispatch_mgt *disp_mgt,
				 u16 num_net_msix, u16 num_others_msix,
				 bool net_msix_mask_en)
{
	struct nbl_resource_ops *res_ops = disp_mgt->res_ops_tbl->ops;
	struct nbl_resource_mgt *p = disp_mgt->res_ops_tbl->priv;
	struct nbl_common_info *common = disp_mgt->common;
	int ret;

	if (!res_ops->cfg_msix_map)
		return -EOPNOTSUPP;
	mutex_lock(&disp_mgt->ops_mutex_lock);
	ret = res_ops->cfg_msix_map(p, common->mgt_pf, num_net_msix,
					  num_others_msix, net_msix_mask_en);
	mutex_unlock(&disp_mgt->ops_mutex_lock);
	return ret;
}

static int
nbl_disp_chan_cfg_msix_map_req(struct nbl_dispatch_mgt *disp_mgt,
			       u16 num_net_msix, u16 num_others_msix,
			       bool net_msix_mask_en)
{
	struct nbl_channel_ops *chan_ops = disp_mgt->chan_ops_tbl->ops;
	struct nbl_common_info *common = disp_mgt->common;
	struct nbl_chan_param_cfg_msix_map param = { 0 };
	struct nbl_chan_send_info chan_send = {0};
	int ret;

	param.num_net_msix = cpu_to_le16(num_net_msix);
	param.num_others_msix = cpu_to_le16(num_others_msix);
	param.msix_mask_en = cpu_to_le16(!!net_msix_mask_en);

	nbl_chan_fill_send_info(&chan_send, common->mgt_pf,
				NBL_CHAN_MSG_CONFIGURE_MSIX_MAP,
				&param, sizeof(param),
				NULL, 0, 1);
	ret = chan_ops->send_msg(disp_mgt->chan_ops_tbl->priv, &chan_send);
	if (ret)
		return ret;
	return 0;
}

/*
 * Precondition: caller must disable mailbox IRQ_RDY and switch send_msg
 * to polling path before issuing cfg_msix_map RPC.
 * The responder will disable mailbox MSIX routing during resource ops,
 * so ACK cannot rely on interrupt wakeup.
 */
static void nbl_disp_chan_cfg_msix_map_resp(void *priv, u16 src_id, u16 msg_id,
					    void *data, u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = disp_mgt->chan_ops_tbl->ops;
	struct nbl_resource_ops *res_ops = disp_mgt->res_ops_tbl->ops;
	struct nbl_resource_mgt *p = disp_mgt->res_ops_tbl->priv;
	struct device *dev = disp_mgt->common->dev;
	struct nbl_chan_param_cfg_msix_map param = { 0 };
	struct nbl_chan_ack_info chan_ack;
	int err = 0;
	u32 rel_pf_id;
	int ret;

	ret = nbl_common_func_id_to_rel_pf_id(disp_mgt->common, src_id,
					      &rel_pf_id);
	if (ret) {
		err = -EPERM;
		goto ack_out;
	}
	if (rel_pf_id >= disp_mgt->common->max_pf) {
		err = -EPERM;
		goto ack_out;
	}
	if (data_len < sizeof(param)) {
		err = -EREMOTEIO;
		goto ack_out;
	}
	memcpy(&param, data, sizeof(param));

	if (res_ops->cfg_msix_map) {
		mutex_lock(&disp_mgt->ops_mutex_lock);
		ret = res_ops->cfg_msix_map(p, src_id,
					    le16_to_cpu(param.num_net_msix),
					    le16_to_cpu(param.num_others_msix),
					    !!le16_to_cpu(param.msix_mask_en));
		mutex_unlock(&disp_mgt->ops_mutex_lock);
		if (ret)
			err = -EREMOTEIO;
	} else {
		err = -EOPNOTSUPP;
	}
ack_out:
	nbl_chan_fill_ack_info(&chan_ack, src_id,
			       NBL_CHAN_MSG_CONFIGURE_MSIX_MAP, msg_id,
			       err, NULL, 0);
	ret = chan_ops->send_ack(disp_mgt->chan_ops_tbl->priv, &chan_ack);
	if (ret)
		dev_err(dev,
			"channel send ack failed with ret: %d, msg_type: %d\n",
			ret, NBL_CHAN_MSG_CONFIGURE_MSIX_MAP);
}

static int nbl_disp_chan_destroy_msix_map_req(struct nbl_dispatch_mgt *disp_mgt)
{
	struct nbl_channel_ops *chan_ops = disp_mgt->chan_ops_tbl->ops;
	struct nbl_common_info *common = disp_mgt->common;
	struct nbl_chan_send_info chan_send = {0};
	int ret;

	nbl_chan_fill_send_info(&chan_send, common->mgt_pf,
				NBL_CHAN_MSG_DESTROY_MSIX_MAP,
				NULL, 0, NULL, 0, 1);
	ret = chan_ops->send_msg(disp_mgt->chan_ops_tbl->priv, &chan_send);
	if (ret)
		return ret;
	return 0;
}

/*
 * Precondition: caller must disable mailbox IRQ_RDY and switch send_msg
 * to polling path before issuing destroy_msix_map.
 * The responder will disable mailbox MSIX routing during resource ops,
 * so ACK cannot rely on interrupt wakeup.
 */
static void nbl_disp_chan_destroy_msix_map_resp(void *priv, u16 src_id,
						u16 msg_id, void *data,
						u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = disp_mgt->chan_ops_tbl->ops;
	struct nbl_resource_ops *res_ops = disp_mgt->res_ops_tbl->ops;
	struct nbl_resource_mgt *p = disp_mgt->res_ops_tbl->priv;
	struct device *dev = disp_mgt->common->dev;
	struct nbl_chan_ack_info chan_ack;
	int err = 0;
	u32 rel_pf_id;
	int ret;

	ret = nbl_common_func_id_to_rel_pf_id(disp_mgt->common, src_id,
					      &rel_pf_id);
	if (ret) {
		err = -EPERM;
		goto ack_out;
	}
	if (rel_pf_id >= disp_mgt->common->max_pf) {
		err = -EPERM;
		goto ack_out;
	}
	if (res_ops->destroy_msix_map) {
		mutex_lock(&disp_mgt->ops_mutex_lock);
		ret = res_ops->destroy_msix_map(p, src_id);
		mutex_unlock(&disp_mgt->ops_mutex_lock);
		if (ret)
			err = -EREMOTEIO;
	} else {
		err = -EOPNOTSUPP;
	}
ack_out:
	nbl_chan_fill_ack_info(&chan_ack, src_id,
			       NBL_CHAN_MSG_DESTROY_MSIX_MAP, msg_id,
			       err, NULL, 0);
	ret = chan_ops->send_ack(disp_mgt->chan_ops_tbl->priv, &chan_ack);
	if (ret)
		dev_err(dev,
			"channel send ack failed with ret: %d, msg_type: %d\n",
			ret, NBL_CHAN_MSG_DESTROY_MSIX_MAP);
}

static int nbl_disp_chan_set_mailbox_irq_req(struct nbl_dispatch_mgt *disp_mgt,
					     u16 vector_id, bool en_msix)
{
	struct nbl_channel_ops *chan_ops = disp_mgt->chan_ops_tbl->ops;
	struct nbl_chan_param_set_mailbox_irq param = { 0 };
	struct nbl_common_info *common = disp_mgt->common;
	struct nbl_chan_send_info chan_send = {0};
	int ret;

	param.vector_id = cpu_to_le16(vector_id);
	param.en_msix = !!en_msix;

	nbl_chan_fill_send_info(&chan_send, common->mgt_pf,
				NBL_CHAN_MSG_MAILBOX_SET_IRQ,
				&param, sizeof(param), NULL, 0, 1);
	ret = chan_ops->send_msg(disp_mgt->chan_ops_tbl->priv, &chan_send);
	if (ret)
		return ret;
	return 0;
}

static void nbl_disp_chan_set_mailbox_irq_resp(void *priv, u16 src_id,
					       u16 msg_id, void *data,
					       u32 data_len)
{
	struct nbl_dispatch_mgt *disp_mgt = (struct nbl_dispatch_mgt *)priv;
	struct nbl_channel_ops *chan_ops = disp_mgt->chan_ops_tbl->ops;
	struct nbl_resource_ops *res_ops = disp_mgt->res_ops_tbl->ops;
	struct nbl_resource_mgt *p = disp_mgt->res_ops_tbl->priv;
	struct nbl_chan_param_set_mailbox_irq param = { 0 };
	struct device *dev = disp_mgt->common->dev;
	struct nbl_chan_ack_info chan_ack;
	int err = 0;
	u16 vector_id;
	u32 rel_pf_id;
	bool en_msix;
	int ret;

	ret = nbl_common_func_id_to_rel_pf_id(disp_mgt->common, src_id,
					      &rel_pf_id);
	if (ret) {
		err = -EPERM;
		goto ack_out;
	}
	if (rel_pf_id >= disp_mgt->common->max_pf) {
		err = -EPERM;
		goto ack_out;
	}
	if (data_len < sizeof(param)) {
		err = -EREMOTEIO;
		goto ack_out;
	}
	memcpy(&param, data, sizeof(param));
	vector_id = le16_to_cpu(param.vector_id);
	en_msix = !!param.en_msix;

	if (res_ops->set_mailbox_irq) {
		mutex_lock(&disp_mgt->ops_mutex_lock);
		ret = res_ops->set_mailbox_irq(p, src_id, vector_id, en_msix);
		mutex_unlock(&disp_mgt->ops_mutex_lock);
		if (ret)
			err = -EREMOTEIO;
	} else {
		err = -EOPNOTSUPP;
	}

ack_out:
	nbl_chan_fill_ack_info(&chan_ack, src_id,
			       NBL_CHAN_MSG_MAILBOX_SET_IRQ, msg_id,
			       err, NULL, 0);
	ret = chan_ops->send_ack(disp_mgt->chan_ops_tbl->priv, &chan_ack);
	if (ret)
		dev_err(dev,
			"channel send ack failed with ret: %d, msg_type: %d\n",
			ret, NBL_CHAN_MSG_MAILBOX_SET_IRQ);
}

static int nbl_disp_destroy_msix_map(struct nbl_dispatch_mgt *disp_mgt)
{
	struct nbl_resource_ops *res_ops = disp_mgt->res_ops_tbl->ops;
	struct nbl_resource_mgt *p = disp_mgt->res_ops_tbl->priv;
	struct nbl_common_info *common = disp_mgt->common;
	int ret;

	if (!res_ops->destroy_msix_map)
		return -EOPNOTSUPP;
	mutex_lock(&disp_mgt->ops_mutex_lock);
	ret = res_ops->destroy_msix_map(p, common->mgt_pf);
	mutex_unlock(&disp_mgt->ops_mutex_lock);
	return ret;
}

static int nbl_disp_set_mailbox_irq(struct nbl_dispatch_mgt *disp_mgt,
				    u16 vector_id, bool en_msix)
{
	struct nbl_resource_ops *res_ops = disp_mgt->res_ops_tbl->ops;
	struct nbl_resource_mgt *p = disp_mgt->res_ops_tbl->priv;
	struct nbl_common_info *common = disp_mgt->common;
	int ret;

	if (!res_ops->set_mailbox_irq)
		return -EOPNOTSUPP;
	mutex_lock(&disp_mgt->ops_mutex_lock);
	ret = res_ops->set_mailbox_irq(p, common->mgt_pf, vector_id, en_msix);
	mutex_unlock(&disp_mgt->ops_mutex_lock);
	return ret;
}

static int nbl_disp_get_vsi_id(struct nbl_dispatch_mgt *disp_mgt, u16 type,
			       u16 *vsi_id)
{
	struct nbl_resource_ops *res_ops = disp_mgt->res_ops_tbl->ops;
	struct nbl_resource_mgt *p = disp_mgt->res_ops_tbl->priv;
	struct nbl_common_info *common = disp_mgt->common;

	if (res_ops->get_vsi_id)
		return res_ops->get_vsi_id(p, common->mgt_pf, type, vsi_id);
	return -EOPNOTSUPP;
}

static int nbl_disp_get_eth_id(struct nbl_dispatch_mgt *disp_mgt, u16 vsi_id,
			       u8 *eth_num, u8 *eth_id, u8 *logic_eth_id)
{
	struct nbl_resource_ops *res_ops = disp_mgt->res_ops_tbl->ops;
	struct nbl_resource_mgt *p = disp_mgt->res_ops_tbl->priv;
	struct nbl_common_info *common = disp_mgt->common;

	if (res_ops->get_eth_id)
		return res_ops->get_eth_id(p, common->mgt_pf, vsi_id,
					   eth_num, eth_id, logic_eth_id);
	return -EOPNOTSUPP;
}

static int nbl_disp_setup_msg(struct nbl_dispatch_mgt *disp_mgt)
{
	struct nbl_channel_ops *chan_ops = disp_mgt->chan_ops_tbl->ops;
	struct nbl_channel_mgt *p = disp_mgt->chan_ops_tbl->priv;
	int ret = 0;
	int _ret;

	_ret = chan_ops->register_msg(p, NBL_CHAN_MSG_CONFIGURE_MSIX_MAP,
				      nbl_disp_chan_cfg_msix_map_resp,
				      disp_mgt);
	if (_ret < 0 && !ret)
		ret = _ret;

	_ret = chan_ops->register_msg(p, NBL_CHAN_MSG_DESTROY_MSIX_MAP,
				      nbl_disp_chan_destroy_msix_map_resp,
				      disp_mgt);
	if (_ret < 0 && !ret)
		ret = _ret;

	_ret = chan_ops->register_msg(p, NBL_CHAN_MSG_MAILBOX_SET_IRQ,
				      nbl_disp_chan_set_mailbox_irq_resp,
				      disp_mgt);
	if (_ret < 0 && !ret)
		ret = _ret;

	_ret = chan_ops->register_msg(p, NBL_CHAN_MSG_GET_VSI_ID,
				      nbl_disp_chan_get_vsi_id_resp,
				      disp_mgt);
	if (_ret < 0 && !ret)
		ret = _ret;

	_ret = chan_ops->register_msg(p, NBL_CHAN_MSG_GET_ETH_ID,
				      nbl_disp_chan_get_eth_id_resp,
				      disp_mgt);
	if (_ret < 0 && !ret)
		ret = _ret;

	return ret;
}

static void nbl_disp_set_ctrl_bit(struct nbl_dispatch_mgt *disp_mgt, u32 lvl)
{
	set_bit(lvl, disp_mgt->ctrl_lvl);
}

static void nbl_disp_refresh_ctrl_ops(struct nbl_dispatch_mgt *disp_mgt)
{
	struct nbl_dispatch_ops *disp_ops = disp_mgt->disp_ops_tbl->ops;

	memset(disp_ops, 0, sizeof(*disp_ops));
	if (test_bit(NBL_DISP_CTRL_LVL_MGT, disp_mgt->ctrl_lvl)) {
		disp_ops->init_module = nbl_disp_init_module;
		disp_ops->deinit_module = nbl_disp_deinit_module;
		disp_ops->cfg_msix_map = nbl_disp_cfg_msix_map;
		disp_ops->destroy_msix_map = nbl_disp_destroy_msix_map;
		disp_ops->set_mailbox_irq = nbl_disp_set_mailbox_irq;
		disp_ops->get_vsi_id = nbl_disp_get_vsi_id;
		disp_ops->get_eth_id = nbl_disp_get_eth_id;
	} else if (test_bit(NBL_DISP_CTRL_LVL_NET, disp_mgt->ctrl_lvl)) {
		disp_ops->cfg_msix_map =
			nbl_disp_chan_cfg_msix_map_req;
		disp_ops->destroy_msix_map = nbl_disp_chan_destroy_msix_map_req;
		disp_ops->set_mailbox_irq = nbl_disp_chan_set_mailbox_irq_req;
		disp_ops->get_vsi_id = nbl_disp_chan_get_vsi_id_req;
		disp_ops->get_eth_id = nbl_disp_chan_get_eth_id_req;
	}
}

static struct nbl_dispatch_mgt *
nbl_disp_setup_disp_mgt(struct nbl_common_info *common)
{
	struct nbl_dispatch_mgt *disp_mgt;
	struct device *dev = common->dev;
	int err;

	disp_mgt = devm_kzalloc(dev, sizeof(*disp_mgt), GFP_KERNEL);
	if (!disp_mgt)
		return ERR_PTR(-ENOMEM);

	disp_mgt->common = common;
	err = devm_mutex_init(common->dev, &disp_mgt->ops_mutex_lock);
	if (err)
		return ERR_PTR(err);
	return disp_mgt;
}

static struct nbl_dispatch_ops_tbl *
nbl_disp_setup_ops(struct device *dev, struct nbl_dispatch_mgt *disp_mgt)
{
	struct nbl_dispatch_ops_tbl *disp_ops_tbl;
	struct nbl_dispatch_ops *disp_ops;

	disp_ops_tbl = devm_kzalloc(dev, sizeof(*disp_ops_tbl), GFP_KERNEL);
	if (!disp_ops_tbl)
		return ERR_PTR(-ENOMEM);

	disp_ops = devm_kzalloc(dev, sizeof(*disp_ops), GFP_KERNEL);
	if (!disp_ops)
		return ERR_PTR(-ENOMEM);

	disp_ops_tbl->ops = disp_ops;
	disp_ops_tbl->priv = disp_mgt;

	return disp_ops_tbl;
}

int nbl_disp_init(struct nbl_adapter *adapter)
{
	struct nbl_common_info *common = &adapter->common;
	struct nbl_dispatch_ops_tbl *disp_ops_tbl;
	struct nbl_resource_ops_tbl *res_ops_tbl =
		adapter->intf.resource_ops_tbl;
	struct nbl_channel_ops_tbl *chan_ops_tbl =
		adapter->intf.channel_ops_tbl;
	struct device *dev = &adapter->pdev->dev;
	struct nbl_dispatch_mgt *disp_mgt;
	int ret;

	disp_mgt = nbl_disp_setup_disp_mgt(common);
	if (IS_ERR(disp_mgt)) {
		ret = PTR_ERR(disp_mgt);
		return ret;
	}

	disp_ops_tbl = nbl_disp_setup_ops(dev, disp_mgt);
	if (IS_ERR(disp_ops_tbl)) {
		ret = PTR_ERR(disp_ops_tbl);
		return ret;
	}

	disp_mgt->res_ops_tbl = res_ops_tbl;
	disp_mgt->chan_ops_tbl = chan_ops_tbl;
	disp_mgt->disp_ops_tbl = disp_ops_tbl;
	adapter->core.disp_mgt = disp_mgt;
	adapter->intf.dispatch_ops_tbl = disp_ops_tbl;

	ret = nbl_disp_setup_msg(disp_mgt);
	if (ret)
		return ret;

	if (common->has_ctrl)
		nbl_disp_set_ctrl_bit(disp_mgt, NBL_DISP_CTRL_LVL_MGT);

	if (common->has_net)
		nbl_disp_set_ctrl_bit(disp_mgt, NBL_DISP_CTRL_LVL_NET);
	nbl_disp_refresh_ctrl_ops(disp_mgt);
	return 0;
}

void nbl_disp_remove(struct nbl_adapter *adapter)
{
	/*
	 * Dispatch structures are allocated via devm.
	 * Message handlers registered by nbl_disp_setup_msg() are owned by
	 * channel layer; they are unregistered in nbl_chan_remove_common(),
	 * not here.
	 */
}
