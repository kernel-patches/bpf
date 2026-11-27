// SPDX-License-Identifier: MIT
/*
 * Copyright © 2024 Intel Corporation
 */
#include <linux/sysfs.h>
#include <drm/drm_managed.h>

#include "xe_device_types.h"
#include "xe_pcode.h"
#include "xe_pcode_api.h"
#include "xe_pm.h"
#include "xe_tile_sysfs.h"
#include "xe_vram_config.h"

/**
 * DOC: Xe VRAM config
 *
 * Provides sysfs entries for vram frequency and bandwidth in tile
 *
 * device/tile#/memory/freq0/max_freq - This is maximum frequency. This value is read-only as it
 *					is the fixed fuse point P0. It is not the system
 *					configuration.
 * device/tile#/memory/freq0/min_freq - This is minimum frequency. This value is read-only as it
 *					is the fixed fuse point PN. It is not the system
 *					configuration.
 *
 * On Crescent Island, the following entries are provided instead:
 *
 * device/tile#/memory/max_freq - Maximum achievable memory frequency in MHz. Read-only.
 * device/tile#/memory/max_bw - Maximum achievable memory bandwidth in Mbps. Read-only.
 */

static struct xe_tile *kobj_to_tile_parent(struct kobject *kobj)
{
	return kobj_to_tile(kobj->parent);
}

static ssize_t max_freq_show(struct kobject *kobj, struct kobj_attribute *attr,
			     char *buf)
{
	struct xe_tile *tile = kobj_to_tile_parent(kobj);
	u32 val = 0, mbox;
	int err;

	mbox = REG_FIELD_PREP(PCODE_MB_COMMAND, PCODE_FREQUENCY_CONFIG)
		| REG_FIELD_PREP(PCODE_MB_PARAM1, PCODE_MBOX_FC_SC_READ_FUSED_P0)
		| REG_FIELD_PREP(PCODE_MB_PARAM2, PCODE_MBOX_DOMAIN_HBM);

	err = xe_pcode_read(tile, mbox, &val, NULL);
	if (err)
		return err;

	/* data_out - Fused P0 for domain ID in units of 50 MHz */
	val *= 50;

	return sysfs_emit(buf, "%u\n", val);
}

static struct kobj_attribute kobj_attr_max_freq = {
	.attr = { .name = "max_freq", .mode = 0444 },
	.show = max_freq_show,
};

static ssize_t min_freq_show(struct kobject *kobj, struct kobj_attribute *attr,
			     char *buf)
{
	struct xe_tile *tile = kobj_to_tile_parent(kobj);
	u32 val = 0, mbox;
	int err;

	mbox = REG_FIELD_PREP(PCODE_MB_COMMAND, PCODE_FREQUENCY_CONFIG)
		| REG_FIELD_PREP(PCODE_MB_PARAM1, PCODE_MBOX_FC_SC_READ_FUSED_PN)
		| REG_FIELD_PREP(PCODE_MB_PARAM2, PCODE_MBOX_DOMAIN_HBM);

	err = xe_pcode_read(tile, mbox, &val, NULL);
	if (err)
		return err;

	/* data_out - Fused Pn for domain ID in units of 50 MHz */
	val *= 50;

	return sysfs_emit(buf, "%u\n", val);
}

static struct kobj_attribute kobj_attr_min_freq = {
	.attr = { .name = "min_freq", .mode = 0444 },
	.show = min_freq_show,
};

static struct attribute *freq_attrs[] = {
	&kobj_attr_max_freq.attr,
	&kobj_attr_min_freq.attr,
	NULL
};

static const struct attribute_group freq_group_attrs = {
	.name = "freq0",
	.attrs = freq_attrs,
};

static const struct attribute_group *pvc_memory_groups[] = {
	&freq_group_attrs,
	NULL
};

static int memory_config_read(struct kobject *kobj, u32 subcmd, u32 *val)
{
	struct xe_tile *tile = kobj_to_tile_parent(kobj);

	guard(xe_pm_runtime)(tile_to_xe(tile));

	return xe_pcode_read(tile, PCODE_MBOX(PCODE_MEMORY_CONFIG, subcmd, 0),
			     val, NULL);
}

static ssize_t cri_max_freq_show(struct kobject *kobj, struct kobj_attribute *attr,
				 char *buf)
{
	u32 val = 0;
	int err;

	err = memory_config_read(kobj, MEMORY_CONFIG_SUBCOMMAND_READ_MAX_FREQUENCY, &val);
	if (err)
		return err;

	return sysfs_emit(buf, "%u\n", val);
}

static struct kobj_attribute kobj_attr_cri_max_freq = {
	.attr = { .name = "max_freq", .mode = 0444 },
	.show = cri_max_freq_show,
};

static ssize_t max_bw_show(struct kobject *kobj, struct kobj_attribute *attr,
			   char *buf)
{
	u32 val = 0;
	int err;

	err = memory_config_read(kobj, MEMORY_CONFIG_SUBCOMMAND_READ_MAX_BANDWIDTH, &val);
	if (err)
		return err;

	return sysfs_emit(buf, "%u\n", val);
}

static struct kobj_attribute kobj_attr_max_bw = {
	.attr = { .name = "max_bw", .mode = 0444 },
	.show = max_bw_show,
};

static struct attribute *cri_memory_attrs[] = {
	&kobj_attr_cri_max_freq.attr,
	&kobj_attr_max_bw.attr,
	NULL
};

static const struct attribute_group cri_memory_group_attrs = {
	.attrs = cri_memory_attrs,
};

static const struct attribute_group *cri_memory_groups[] = {
	&cri_memory_group_attrs,
	NULL
};

static const struct attribute_group **memory_groups(struct xe_device *xe)
{
	if (xe->info.skip_pcode)
		return NULL;

	if (xe->info.platform == XE_PVC)
		return pvc_memory_groups;
	if (xe->info.platform == XE_CRESCENTISLAND)
		return cri_memory_groups;
	return NULL;
}

static void vram_freq_sysfs_fini(void *arg)
{
	struct kobject *kobj = arg;
	struct xe_tile *tile = kobj_to_tile(kobj->parent);

	sysfs_remove_groups(kobj, memory_groups(tile_to_xe(tile)));
	kobject_put(kobj);
}

/**
 * xe_vram_config_sysfs_init - Initialize vram configuration sysfs component
 * @tile: Xe Tile object
 *
 * It needs to be initialized after the main tile component is ready
 *
 * Returns: 0 on success, negative error code on error.
 */
int xe_vram_config_sysfs_init(struct xe_tile *tile)
{
	struct xe_device *xe = tile_to_xe(tile);
	const struct attribute_group **groups = memory_groups(xe);
	struct kobject *kobj;
	int err;

	if (!groups)
		return 0;

	kobj = kobject_create_and_add("memory", tile->sysfs);
	if (!kobj)
		return -ENOMEM;

	err = sysfs_create_groups(kobj, groups);
	if (err) {
		kobject_put(kobj);
		return err;
	}

	return devm_add_action_or_reset(xe->drm.dev, vram_freq_sysfs_fini, kobj);
}
