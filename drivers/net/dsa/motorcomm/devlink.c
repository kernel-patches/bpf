// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2026 David Yang
 */

#include "chip.h"
#include "devlink.h"
#include "smi.h"
#include "tc.h"

#define to_yt921x_priv(_ds) container_of_const(_ds, struct yt921x_priv, ds)

int
yt921x_dsa_devlink_info_get(struct dsa_switch *ds, struct devlink_info_req *req,
			    struct netlink_ext_ack *extack)
{
	struct yt921x_priv *priv = to_yt921x_priv(ds);
	int res;

	if (!priv->info)
		return -ENODEV;

	res = devlink_info_version_fixed_put(req,
					     DEVLINK_INFO_VERSION_GENERIC_ASIC_ID,
					     priv->info->name);
	if (res)
		return res;

	return 0;
}

static u64 yt921x_devlink_occ_get_acl(void *ctx)
{
	struct yt921x_priv *priv = ctx;
	u64 count = 0;

	mutex_lock(&priv->reg_lock);
	for (unsigned int i = 0; i < YT921X_ACL_BLK_NUM; i++)
		count += hweight8(priv->acl_masks[i]);
	mutex_unlock(&priv->reg_lock);

	return count;
}

static u64 yt921x_devlink_occ_get_fdb_ucast(void *ctx)
{
	struct yt921x_priv *priv = ctx;
	u32 val;
	int res;

	mutex_lock(&priv->reg_lock);
	res = yt921x_reg_read(priv, YT921X_LEARN_UCAST_CNT, &val);
	mutex_unlock(&priv->reg_lock);

	if (res)
		return 0;
	return val;
}

static u64 yt921x_devlink_occ_get_fdb_mcast(void *ctx)
{
	struct yt921x_priv *priv = ctx;
	u32 val;
	int res;

	mutex_lock(&priv->reg_lock);
	res = yt921x_reg_read(priv, YT921X_LEARN_MCAST_CNT, &val);
	mutex_unlock(&priv->reg_lock);

	if (res)
		return 0;
	return val;
}

static u64 yt921x_devlink_occ_get_fdb_static(void *ctx)
{
	struct yt921x_priv *priv = ctx;

	return READ_ONCE(priv->fdb_static_cnt);
}

static u64 yt921x_devlink_occ_get_fdb(void *ctx)
{
	struct yt921x_priv *priv = ctx;
	u64 count = 0;
	u32 val;
	int res;

	mutex_lock(&priv->reg_lock);

	res = yt921x_reg_read(priv, YT921X_LEARN_UCAST_CNT, &val);
	if (res)
		goto end;
	count += val;

	res = yt921x_reg_read(priv, YT921X_LEARN_MCAST_CNT, &val);
	if (res)
		goto end;
	count += val;

	count += priv->fdb_static_cnt;

end:
	mutex_unlock(&priv->reg_lock);

	if (res)
		return 0;
	return count;
}

static u64 yt921x_devlink_occ_get_meter(void *ctx)
{
	struct yt921x_priv *priv = ctx;
	u64 count;

	mutex_lock(&priv->reg_lock);
	count = bitmap_weight(priv->meters_map, YT921X_METER_NUM);
	mutex_unlock(&priv->reg_lock);

	return count;
}

enum yt921x_devlink_resource_id {
	YT921X_DEVLINK_RESOURCE_ID_NONE,  /* DEVLINK_RESOURCE_ID_PARENT_TOP */
	YT921X_DEVLINK_RESOURCE_ID_ACL,
	YT921X_DEVLINK_RESOURCE_ID_FDB,
	YT921X_DEVLINK_RESOURCE_ID_FDB_UCAST,
	YT921X_DEVLINK_RESOURCE_ID_FDB_MCAST,
	YT921X_DEVLINK_RESOURCE_ID_FDB_STATIC,
	YT921X_DEVLINK_RESOURCE_ID_METER,
};

struct yt921x_devlink_resource {
	const char *name;
	devlink_resource_occ_get_t *occ_get;
	unsigned short size;
	unsigned char id;
	unsigned char parent_id;
};

static const struct yt921x_devlink_resource yt921x_devlink_resources[] = {
	{
		"ACLs", yt921x_devlink_occ_get_acl,
		YT921X_ACL_NUM,
		YT921X_DEVLINK_RESOURCE_ID_ACL,
		DEVLINK_RESOURCE_ID_PARENT_TOP,
	},
	{
		"FDBs", yt921x_devlink_occ_get_fdb,
		YT921X_FDB_NUM,
		YT921X_DEVLINK_RESOURCE_ID_FDB,
		DEVLINK_RESOURCE_ID_PARENT_TOP,
	},
	{
		"ucast", yt921x_devlink_occ_get_fdb_ucast,
		YT921X_FDB_NUM,
		YT921X_DEVLINK_RESOURCE_ID_FDB_UCAST,
		YT921X_DEVLINK_RESOURCE_ID_FDB,
	},
	{
		"mcast", yt921x_devlink_occ_get_fdb_mcast,
		YT921X_FDB_NUM,
		YT921X_DEVLINK_RESOURCE_ID_FDB_MCAST,
		YT921X_DEVLINK_RESOURCE_ID_FDB,
	},
	{
		"static", yt921x_devlink_occ_get_fdb_static,
		YT921X_FDB_NUM,
		YT921X_DEVLINK_RESOURCE_ID_FDB_STATIC,
		YT921X_DEVLINK_RESOURCE_ID_FDB,
	},
	{
		"meters", yt921x_devlink_occ_get_meter,
		YT921X_METER_NUM,
		YT921X_DEVLINK_RESOURCE_ID_METER,
		DEVLINK_RESOURCE_ID_PARENT_TOP,
	},
};

int yt921x_devlink_setup(struct yt921x_priv *priv)
{
	struct dsa_switch *ds = &priv->ds;
	int res;

	for (unsigned int i = 0; i < ARRAY_SIZE(yt921x_devlink_resources);
	     i++) {
		struct devlink_resource_size_params size_params;
		const struct yt921x_devlink_resource *r;

		r = &yt921x_devlink_resources[i];

		devlink_resource_size_params_init(&size_params, r->size,
						  r->size, 1,
						  DEVLINK_RESOURCE_UNIT_ENTRY);

		res = dsa_devlink_resource_register(ds, r->name, r->size, r->id,
						    r->parent_id, &size_params);
		if (res) {
			dsa_devlink_resources_unregister(ds);
			return res;
		}

		dsa_devlink_resource_occ_get_register(ds, r->id, r->occ_get,
						      priv);
	}

	return 0;
}
