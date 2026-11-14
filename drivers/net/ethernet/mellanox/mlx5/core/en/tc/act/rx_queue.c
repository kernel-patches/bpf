// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB

#include "act.h"
#include "en/tc_priv.h"
#include "en/rx_res.h"

static bool
tc_act_can_offload_rx_queue(struct mlx5e_tc_act_parse_state *parse_state,
			    const struct flow_action_entry *act,
			    int act_index,
			    struct mlx5_flow_attr *attr)
{
	struct netlink_ext_ack *extack = parse_state->extack;
	struct mlx5e_tc_flow *flow = parse_state->flow;

	/* The direct TIR takes over the destination of the rule */
	if (!flow_action_is_last_entry(parse_state->flow_action, act) ||
	    attr->dest_chain || flow_flag_test(flow, HAIRPIN)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "RX queue mapping must be the last action and cannot follow goto or mirred");
		return false;
	}

	if (act->rx_queue >= flow->priv->channels.params.num_channels) {
		NL_SET_ERR_MSG_MOD(extack, "RX queue index out of range");
		return false;
	}

	return true;
}

static int
tc_act_parse_rx_queue(struct mlx5e_tc_act_parse_state *parse_state,
		      const struct flow_action_entry *act,
		      struct mlx5e_priv *priv,
		      struct mlx5_flow_attr *attr)
{
	attr->nic_attr->rx_tirn = mlx5e_rx_res_get_tirn_direct(priv->rx_res,
							       act->rx_queue);
	attr->action |= MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;

	return 0;
}

struct mlx5e_tc_act mlx5e_tc_act_rx_queue = {
	.can_offload = tc_act_can_offload_rx_queue,
	.parse_action = tc_act_parse_rx_queue,
	.is_terminating_action = true,
};
