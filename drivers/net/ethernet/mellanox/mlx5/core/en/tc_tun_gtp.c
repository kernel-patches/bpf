// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB

#include "en/tc_tun.h"

static int
mlx5e_tc_tun_parse_outer_key_gtp(struct mlx5e_priv *priv,
				 struct mlx5_flow_spec *spec,
				 struct netlink_ext_ack *extack,
				 u32 key, u32 mask,
				 enum fs_flow_table_type fs_type)
{
	void *misc3_c, *misc3_v;

	if (!(MLX5_CAP_GEN(priv->mdev, flex_parser_protocols) &
	      MLX5_FLEX_PARSER_GTPU_TEID_ENABLED)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Matching on GTP-U TEID is not supported");
		return -EOPNOTSUPP;
	}

	misc3_c = MLX5_ADDR_OF(fte_match_param, spec->match_criteria,
			       misc_parameters_3);
	misc3_v = MLX5_ADDR_OF(fte_match_param, spec->match_value,
			       misc_parameters_3);

	MLX5_SET(fte_match_set_misc3, misc3_c, gtpu_teid, mask);
	MLX5_SET(fte_match_set_misc3, misc3_v, gtpu_teid, key);
	spec->match_criteria_enable |= MLX5_MATCH_MISC_PARAMETERS_3;

	return 0;
}

/* The driver offloads no GTP device so this only matches on the wire */
struct mlx5e_tc_tunnel gtp_tunnel = {
	.parse_outer_key = mlx5e_tc_tun_parse_outer_key_gtp,
};
