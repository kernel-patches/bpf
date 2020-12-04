// SPDX-License-Identifier: GPL-2.0-only

#include "netlink.h"
#include "common.h"
#include "bitset.h"

struct properties_req_info {
	struct ethnl_req_info	base;
};

struct properties_reply_data {
	struct ethnl_reply_data	base;
	u32			properties[ETHTOOL_XDP_PROPERTIES_WORDS];
};

const struct nla_policy ethnl_properties_get_policy[] = {
	[ETHTOOL_A_XDP_PROPERTIES_HEADER]	=
		NLA_POLICY_NESTED(ethnl_header_policy),
};

#define PROPERTIES_REPDATA(__reply_base) \
	container_of(__reply_base, struct properties_reply_data, base)

static void ethnl_properties_to_bitmap32(u32 *dest, xdp_properties_t src)
{
	unsigned int i;

	for (i = 0; i < ETHTOOL_XDP_PROPERTIES_WORDS; i++)
		dest[i] = src >> (32 * i);
}

static int properties_prepare_data(const struct ethnl_req_info *req_base,
				   struct ethnl_reply_data *reply_base,
				   struct genl_info *info)
{
	struct properties_reply_data *data = PROPERTIES_REPDATA(reply_base);
	struct net_device *dev = reply_base->dev;

	ethnl_properties_to_bitmap32(data->properties, dev->xdp_properties);

	return 0;
}

static int properties_reply_size(const struct ethnl_req_info *req_base,
				 const struct ethnl_reply_data *reply_base)
{
	const struct properties_reply_data *data = PROPERTIES_REPDATA(reply_base);
	bool compact = req_base->flags & ETHTOOL_FLAG_COMPACT_BITSETS;

	return ethnl_bitset32_size(data->properties, NULL, XDP_PROPERTIES_COUNT,
				   xdp_properties_strings, compact);
}

static int properties_fill_reply(struct sk_buff *skb,
				 const struct ethnl_req_info *req_base,
				 const struct ethnl_reply_data *reply_base)
{
	const struct properties_reply_data *data = PROPERTIES_REPDATA(reply_base);
	bool compact = req_base->flags & ETHTOOL_FLAG_COMPACT_BITSETS;

	return ethnl_put_bitset32(skb, ETHTOOL_A_XDP_PROPERTIES_DATA, data->properties,
				  NULL, XDP_PROPERTIES_COUNT,
				  xdp_properties_strings, compact);
}

const struct ethnl_request_ops ethnl_xdp_request_ops = {
	.request_cmd		= ETHTOOL_MSG_XDP_PROPERTIES_GET,
	.reply_cmd		= ETHTOOL_MSG_XDP_PROPERTIES_GET_REPLY,
	.hdr_attr		= ETHTOOL_A_XDP_PROPERTIES_HEADER,
	.req_info_size		= sizeof(struct properties_req_info),
	.reply_data_size	= sizeof(struct properties_reply_data),

	.prepare_data		= properties_prepare_data,
	.reply_size		= properties_reply_size,
	.fill_reply		= properties_fill_reply,
};
