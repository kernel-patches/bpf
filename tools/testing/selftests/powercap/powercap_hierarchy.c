// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * Author: Daniel Lezcano <daniel.lezcano@oss.qualcomm.com>
 *
 * Powercap hierarchy description test module
 *
 * Test coverage:
 * - Duplicate an init-only description for use after module initialization.
 * - Create and destroy a hierarchy directly from a static initializer.
 * - Skip a cluster and its children while creating independent branches.
 * - Destroy the partial hierarchy and create the complete hierarchy again.
 * - Reject repeated creation with -EBUSY and preserve existing zone pointers.
 * - Check callback arguments and preservation of backend-private data.
 *
 * The complete hierarchy remains registered for powercap_hierarchy.sh to
 * check its 16 zones and exported attribute values. Module removal destroys
 * it so the script can check cleanup with a sysfs descriptor still open.
 */
#include <linux/powercap.h>
#include <linux/string.h>

struct pch_test_data {
	int value;
};

static struct powercap_node pch_test_nodes[] __initdata = {
	[0] = { .name = "package",
		.data = &(struct pch_test_data) { .value = 0xDEADBEEF } },
	[1] = { .name = "cluster0", .parent = &pch_test_nodes[0],
		.data = &(struct pch_test_data) { .value = 0xDEADBEEF } },
	[2] = { .name = "cluster1", .parent = &pch_test_nodes[0],
		.data = &(struct pch_test_data) { .value = 0xDEADBEEF } },
	[3] = { .name = "cluster2", .parent = &pch_test_nodes[0],
		.data = &(struct pch_test_data) { .value = 0xDEADBEEF } },
	[4] = { .name = "cpu0", .parent = &pch_test_nodes[1],
		.data = &(struct pch_test_data) { .value = 0xDEADBEEF } },
	[5] = { .name = "cpu1", .parent = &pch_test_nodes[1],
		.data = &(struct pch_test_data) { .value = 0xDEADBEEF } },
	[6] = { .name = "cpu2", .parent = &pch_test_nodes[1],
		.data = &(struct pch_test_data) { .value = 0xDEADBEEF } },
	[7] = { .name = "cpu3", .parent = &pch_test_nodes[1],
		.data = &(struct pch_test_data) { .value = 0xDEADBEEF } },
	[8] = { .name = "cpu4", .parent = &pch_test_nodes[2],
		.data = &(struct pch_test_data) { .value = 0xDEADBEEF } },
	[9] = { .name = "cpu5", .parent = &pch_test_nodes[2],
		.data = &(struct pch_test_data) { .value = 0xDEADBEEF } },
	[10] = { .name = "cpu6", .parent = &pch_test_nodes[2],
		.data = &(struct pch_test_data) { .value = 0xDEADBEEF } },
	[11] = { .name = "cpu7", .parent = &pch_test_nodes[2],
		.data = &(struct pch_test_data) { .value = 0xDEADBEEF } },
	[12] = { .name = "cpu8", .parent = &pch_test_nodes[3],
		.data = &(struct pch_test_data) { .value = 0xDEADBEEF } },
	[13] = { .name = "cpu9", .parent = &pch_test_nodes[3],
		.data = &(struct pch_test_data) { .value = 0xDEADBEEF } },
	[14] = { .name = "cpu10", .parent = &pch_test_nodes[3],
		.data = &(struct pch_test_data) { .value = 0xDEADBEEF } },
	[15] = { .name = "cpu11", .parent = &pch_test_nodes[3],
		.data = &(struct pch_test_data) { .value = 0xDEADBEEF } },
};

static struct powercap_hierarchy pch_test_description __initdata = {
	.nodes = pch_test_nodes,
	.nr_nodes = ARRAY_SIZE(pch_test_nodes),
};

/* A static mutex's lockdep key must outlive the module's init sections. */
static struct powercap_hierarchy pch_test_hierarchy =
	POWERCAP_HIERARCHY_INIT(pch_test_hierarchy, NULL, 0);

static struct powercap_hierarchy *hierarchy;

static struct powercap_control_type *pct;

static int pch_test_get_max_power_range_uw(struct powercap_zone *pcz,
					   u64 *power_uw)
{
	*power_uw = 0xBADC0FFEE;
	return 0;
}

static int pch_test_get_power_uw(struct powercap_zone *pcz,
				 u64 *power_uw)
{
	*power_uw = 0xC0FFEE;
	return 0;
}

static const struct powercap_zone_ops pch_test_ops = {
	.get_max_power_range_uw = pch_test_get_max_power_range_uw,
	.get_power_uw = pch_test_get_power_uw,
};

static int pch_test_set_power_limit_uw(struct powercap_zone *pcz,
				       int cid, u64 power_uw)
{
	return 0;
}

static int pch_test_get_power_limit_uw(struct powercap_zone *pcz,
				       int cid, u64 *power_uw)
{
	*power_uw = 0xDEADC0DE;
	return 0;
}

static int pch_test_set_time_window_us(struct powercap_zone *pcz,
				       int cid, u64 power_uw)
{
	return 0;
}

static int pch_test_get_time_window_us(struct powercap_zone *pcz,
				       int cid, u64 *power_uw)
{
	*power_uw = 0xDEADC0DE;
	return 0;
}

static int pch_test_get_max_power_uw(struct powercap_zone *pcz,
				     int cid, u64 *power_uw)
{
	*power_uw = 0xDEADC0DE;
	return 0;
}

static const char *pch_test_get_name(struct powercap_zone *pcz, int cid)
{
	return "my constraint name";
}

static const struct powercap_zone_constraint_ops pch_test_constraint_ops = {
	.set_power_limit_uw = pch_test_set_power_limit_uw,
	.get_power_limit_uw = pch_test_get_power_limit_uw,
	.set_time_window_us = pch_test_set_time_window_us,
	.get_time_window_us = pch_test_get_time_window_us,
	.get_max_power_uw = pch_test_get_max_power_uw,
	.get_name = pch_test_get_name,
};

static struct powercap_zone *pch_test_create(struct powercap_control_type *pct,
					     const char *name, void *data,
					     struct powercap_zone *parent)
{
	struct pch_test_data *pcht_data = data;
	struct powercap_zone *pcz;

	/* Validate the arguments and private data supplied by the helper. */
	if (!pct) {
		pr_err("Invalid NULL controller type\n");
		return ERR_PTR(-EINVAL);
	}

	if (!name) {
		pr_err("Invalid NULL name\n");
		return ERR_PTR(-EINVAL);
	}

	if (pcht_data->value != 0xDEADBEEF) {
		pr_err("Invalid pcht data != 0xDEADBEEF");
		return ERR_PTR(-EINVAL);
	}

	pcz = powercap_register_zone(NULL, pct, name, parent,
				     &pch_test_ops, 1, &pch_test_constraint_ops);
	if (IS_ERR(pcz)) {
		pr_err("Failed to register powercap zone '%s': %ld\n",
		       name, PTR_ERR(pcz));
	}

	return pcz;
}

static void pch_test_destroy(struct powercap_control_type *pct,
			     struct powercap_zone *zone,
			     void *data)
{
	struct pch_test_data *pcht_data = data;

	/* Destruction must receive the original private data and a valid zone. */
	if (!pct) {
		pr_err("Invalid NULL controller type\n");
		return;
	}

	if (!zone) {
		pr_err("Invalid NULL zone\n");
		return;
	}

	if (pcht_data->value != 0xDEADBEEF) {
		pr_err("Invalid pcht data != 0xDEADBEEF");
		return;
	}

	powercap_unregister_zone(pct, zone);
}

static struct powercap_zone *
pch_test_skip_cluster(struct powercap_control_type *pct, const char *name,
		      void *data, struct powercap_zone *parent)
{
	if (!strcmp(name, "cluster0"))
		return NULL;

	return pch_test_create(pct, name, data, parent);
}

static int __init pch_test_init(void)
{
	struct powercap_zone *zones[ARRAY_SIZE(pch_test_nodes)];
	size_t i;
	int ret;

	/* Keep a runtime copy whose parent pointers survive init memory release. */
	hierarchy = powercap_hierarchy_dup(&pch_test_description);
	if (IS_ERR(hierarchy)) {
		ret = PTR_ERR(hierarchy);
		pr_err("Failed to dup the hierarchy: %d\n", ret);
		return ret;
	}

	pct = powercap_register_control_type(NULL, "powercap-test", NULL);
	if (IS_ERR(pct)) {
		ret = PTR_ERR(pct);
		pr_err("Failed to register control type: %d\n", ret);
		goto out_free_hierarchy;
	}

	/* Exercise direct creation with a statically initialized hierarchy lock. */
	pch_test_hierarchy.nodes = pch_test_nodes;
	pch_test_hierarchy.nr_nodes = ARRAY_SIZE(pch_test_nodes);
	ret = powercap_hierarchy_create(pct, &pch_test_hierarchy,
					pch_test_create, pch_test_destroy);
	if (ret) {
		pr_err("Failed to create the static hierarchy: %d\n", ret);
		goto out_unregister_pct;
	}

	powercap_hierarchy_destroy(pct, &pch_test_hierarchy, pch_test_destroy);
	pch_test_hierarchy.nodes = NULL;
	pch_test_hierarchy.nr_nodes = 0;

	/* NULL skips cluster0 and its descendants, but not the other clusters. */
	ret = powercap_hierarchy_create(pct, hierarchy,
					pch_test_skip_cluster, pch_test_destroy);
	if (ret)
		goto out_unregister_pct;

	for (i = 0; i < hierarchy->nr_nodes; i++) {
		/* Node 1 is cluster0; nodes 4 through 7 are its four CPUs. */
		bool skipped = i == 1 || (i >= 4 && i <= 7);

		if (!!hierarchy->nodes[i].zone == skipped) {
			pr_err("Unexpected zone state after skipping cluster0\n");
			ret = -EINVAL;
			goto out_destroy_hierarchy;
		}
	}

	/* Partial destruction must leave the hierarchy reusable for a full tree. */
	powercap_hierarchy_destroy(pct, hierarchy, pch_test_destroy);

	ret = powercap_hierarchy_create(pct, hierarchy, pch_test_create, pch_test_destroy);
	if (ret) {
		pr_err("Failed to create the hierarchy: %d\n", ret);
		goto out_unregister_pct;
	}

	/* A second creation must return -EBUSY without replacing any zone. */
	for (i = 0; i < hierarchy->nr_nodes; i++)
		zones[i] = hierarchy->nodes[i].zone;

	ret = powercap_hierarchy_create(pct, hierarchy, pch_test_create, pch_test_destroy);
	if (ret != -EBUSY) {
		pr_err("Expected -EBUSY when recreating the hierarchy, got %d\n", ret);
		ret = -EINVAL;
		goto out_destroy_hierarchy;
	}

	for (i = 0; i < hierarchy->nr_nodes; i++) {
		if (hierarchy->nodes[i].zone != zones[i]) {
			pr_err("Recreation changed an existing zone\n");
			ret = -EINVAL;
			goto out_destroy_hierarchy;
		}
	}

	/* Leave the full tree available for the userspace sysfs checks. */
	return 0;

out_destroy_hierarchy:
	powercap_hierarchy_destroy(pct, hierarchy, pch_test_destroy);
out_unregister_pct:
	powercap_unregister_control_type(pct);
out_free_hierarchy:
	powercap_hierarchy_free(hierarchy);
	return ret;
}
module_init(pch_test_init);

static void __exit pch_test_exit(void)
{
	/* Remove zones before their controller; the script checks disappearance. */
	powercap_hierarchy_destroy(pct, hierarchy, pch_test_destroy);
	powercap_hierarchy_free(hierarchy);
	powercap_unregister_control_type(pct);
}
module_exit(pch_test_exit);

MODULE_DESCRIPTION("Powercap hierarchy test driver");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Daniel Lezcano <daniel.lezcano@oss.qualcomm.com");
