// SPDX-License-Identifier: MIT
/*
 * Copyright © 2026 Intel Corporation
 */

#include <linux/bitmap.h>

#include <drm/drm_drv.h>
#include <drm/drm_managed.h>
#include <drm/drm_print.h>
#include <drm/drm_ras.h>

#include "xe_device_types.h"
#include "xe_drm_ras.h"
#include "xe_ras.h"
#include "xe_wedge.h"

static const char * const error_components[] = DRM_XE_RAS_ERROR_COMPONENT_NAMES;
static const char * const error_severity[] = DRM_XE_RAS_ERROR_SEVERITY_NAMES;

static int drm_ras_counter_get(struct xe_device *xe, struct xe_drm_ras_counter *info,
			       u32 error_id, int *idx)
{
	if (xe_wedged(xe) && !xe_wedge_mode_is_no_reset(xe))
		return -ECANCELED;

	if (!info || !info[error_id].name)
		return -ENOENT;

	/* Must be last */
	if (!drm_dev_enter(&xe->drm, idx))
		return -ENODEV;

	return 0;
}

static void drm_ras_counter_put(int idx)
{
	/* Pair with drm_ras_counter_get() */
	drm_dev_exit(idx);
}

static bool drm_ras_counter_is_valid(u32 severity, u32 component)
{
	if (!in_range(severity, DRM_XE_RAS_ERR_SEV_CORRECTABLE, DRM_XE_RAS_ERR_SEV_MAX))
		return false;

	if (!in_range(component, DRM_XE_RAS_ERR_COMP_CORE_COMPUTE, DRM_XE_RAS_ERR_COMP_MAX - 1))
		return false;

	return true;
}

static int query_error_counter(struct xe_device *xe,
			       enum drm_xe_ras_error_severity severity,
			       u32 error_id, const char **name, u32 *val)
{
	struct xe_drm_ras *ras = &xe->ras.nl_data;
	struct xe_drm_ras_counter *info = ras->info[severity];
	int idx, ret;

	ret = drm_ras_counter_get(xe, info, error_id, &idx);
	if (ret)
		return ret;

	/* Fetch counter from system controller if supported */
	if (xe->info.has_sysctrl)
		ret = xe_ras_get_counter(xe, severity, error_id, val);
	else
		*val = atomic_read(&info[error_id].counter);

	if (!ret)
		*name = info[error_id].name;

	drm_ras_counter_put(idx);
	return ret;
}

static int clear_error_counter(struct xe_device *xe,
			       enum drm_xe_ras_error_severity severity,
			       u32 error_id)
{
	struct xe_drm_ras *ras = &xe->ras.nl_data;
	struct xe_drm_ras_counter *info = ras->info[severity];
	int idx, ret;

	ret = drm_ras_counter_get(xe, info, error_id, &idx);
	if (ret)
		return ret;

	/* Clear counter from system controller if supported */
	if (xe->info.has_sysctrl)
		ret = xe_ras_clear_counter(xe, severity, error_id);
	else
		atomic_set(&info[error_id].counter, 0);

	drm_ras_counter_put(idx);
	return ret;
}

static int query_uncorrectable_error_counter(struct drm_ras_node *ep, u32 error_id,
					     const char **name, u32 *val)
{
	struct xe_device *xe = ep->priv;

	return query_error_counter(xe, DRM_XE_RAS_ERR_SEV_UNCORRECTABLE, error_id, name, val);
}

static int clear_uncorrectable_error_counter(struct drm_ras_node *node, u32 error_id)
{
	struct xe_device *xe = node->priv;

	return clear_error_counter(xe, DRM_XE_RAS_ERR_SEV_UNCORRECTABLE, error_id);
}

static int query_correctable_error_counter(struct drm_ras_node *ep, u32 error_id,
					   const char **name, u32 *val)
{
	struct xe_device *xe = ep->priv;

	return query_error_counter(xe, DRM_XE_RAS_ERR_SEV_CORRECTABLE, error_id, name, val);
}

static int clear_correctable_error_counter(struct drm_ras_node *node, u32 error_id)
{
	struct xe_device *xe = node->priv;

	return clear_error_counter(xe, DRM_XE_RAS_ERR_SEV_CORRECTABLE, error_id);
}

static int query_correctable_error_threshold(struct drm_ras_node *ep, u32 error_id,
					     const char **name, u32 *threshold)
{
	struct xe_device *xe = ep->priv;
	struct xe_drm_ras *ras = &xe->ras.nl_data;
	struct xe_drm_ras_counter *info = ras->info[DRM_XE_RAS_ERR_SEV_CORRECTABLE];
	int idx, ret;

	if (!xe->info.has_sysctrl)
		return -EOPNOTSUPP;

	ret = drm_ras_counter_get(xe, info, error_id, &idx);
	if (ret)
		return ret;

	ret = xe_ras_get_threshold(xe, DRM_XE_RAS_ERR_SEV_CORRECTABLE, error_id, threshold);
	if (!ret)
		*name = info[error_id].name;

	drm_ras_counter_put(idx);
	return ret;
}

static int set_correctable_error_threshold(struct drm_ras_node *ep, u32 error_id, u32 threshold)
{
	struct xe_device *xe = ep->priv;
	struct xe_drm_ras *ras = &xe->ras.nl_data;
	struct xe_drm_ras_counter *info = ras->info[DRM_XE_RAS_ERR_SEV_CORRECTABLE];
	int idx, ret;

	if (!xe->info.has_sysctrl)
		return -EOPNOTSUPP;

	ret = drm_ras_counter_get(xe, info, error_id, &idx);
	if (ret)
		return ret;

	ret = xe_ras_set_threshold(xe, DRM_XE_RAS_ERR_SEV_CORRECTABLE, error_id, threshold);

	drm_ras_counter_put(idx);
	return ret;
}

static struct xe_drm_ras_counter *allocate_and_copy_counters(struct xe_device *xe)
{
	struct xe_drm_ras_counter *counter;
	int i;

	counter = drmm_kcalloc(&xe->drm, DRM_XE_RAS_ERR_COMP_MAX, sizeof(*counter), GFP_KERNEL);
	if (!counter)
		return ERR_PTR(-ENOMEM);

	for (i = DRM_XE_RAS_ERR_COMP_CORE_COMPUTE; i < DRM_XE_RAS_ERR_COMP_MAX; i++) {
		if (!error_components[i])
			continue;

		counter[i].name = error_components[i];
		atomic_set(&counter[i].counter, 0);
	}

	return counter;
}

static int assign_node_params(struct xe_device *xe, struct drm_ras_node *node,
			      const enum drm_xe_ras_error_severity severity)
{
	struct pci_dev *pdev = to_pci_dev(xe->drm.dev);
	struct xe_drm_ras *ras = &xe->ras.nl_data;
	const char *device_name;

	device_name = kasprintf(GFP_KERNEL, "%04x:%02x:%02x.%d",
				pci_domain_nr(pdev->bus), pdev->bus->number,
				PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn));

	if (!device_name)
		return -ENOMEM;

	node->device_name = device_name;
	node->node_name = error_severity[severity];
	node->type = DRM_RAS_NODE_TYPE_ERROR_COUNTER;
	node->error_counter_range.first = DRM_XE_RAS_ERR_COMP_CORE_COMPUTE;
	node->error_counter_range.last = DRM_XE_RAS_ERR_COMP_MAX - 1;
	node->priv = xe;

	ras->info[severity] = allocate_and_copy_counters(xe);
	if (IS_ERR(ras->info[severity]))
		return PTR_ERR(ras->info[severity]);

	if (severity == DRM_XE_RAS_ERR_SEV_CORRECTABLE) {
		node->query_error_counter = query_correctable_error_counter;
		node->clear_error_counter = clear_correctable_error_counter;
		node->query_error_threshold = query_correctable_error_threshold;
		node->set_error_threshold = set_correctable_error_threshold;
	} else {
		node->query_error_counter = query_uncorrectable_error_counter;
		node->clear_error_counter = clear_uncorrectable_error_counter;
	}

	return 0;
}

static void cleanup_node_param(struct drm_ras_node *node)
{
	kfree(node->device_name);
	node->device_name = NULL;
}

static void cleanup_node(struct drm_device *drm, void *node)
{
	drm_ras_node_unregister(node);
	cleanup_node_param(node);
}

static int register_nodes(struct xe_device *xe)
{
	struct xe_drm_ras *ras = &xe->ras.nl_data;
	struct drm_ras_node *node;
	int i, ret;

	for_each_error_severity(i) {
		node = &ras->node[i];

		ret = assign_node_params(xe, node, i);
		if (ret)
			goto free_param;

		ret = drm_ras_node_register(node);
		if (ret)
			goto free_param;

		ret = drmm_add_action_or_reset(&xe->drm, cleanup_node, node);
		if (ret)
			goto null_info;
	}

	return 0;

free_param:
	cleanup_node_param(node);
null_info:
	ras->info[i] = NULL;
	return ret;
}

/**
 * xe_drm_ras_event() - Report drm-ras error event to userspace
 * @xe: xe device structure
 * @component: error component (see &enum drm_xe_ras_error_component)
 * @severity: error severity (see &enum drm_xe_ras_error_severity)
 * @value: value of error counter
 *
 * Report an error-event to userspace.
 */
void xe_drm_ras_event(struct xe_device *xe, u32 component, u32 severity, u32 value)
{
	struct xe_drm_ras *ras = &xe->ras.nl_data;
	struct xe_drm_ras_counter *info;
	struct drm_ras_node *node;
	int idx, ret;

	/* Event is supported only if drm-ras is enabled */
	if (!xe->info.has_drm_ras)
		return;

	if (!drm_ras_counter_is_valid(severity, component))
		return;

	node = &ras->node[severity];
	info = ras->info[severity];

	ret = drm_ras_counter_get(xe, info, component, &idx);
	if (ret)
		return;

	ret = drm_ras_nl_error_event(node, component, info[component].name, value);
	if (ret)
		drm_err_ratelimited(&xe->drm, "drm-ras error-event failed: %d for %s %s\n", ret,
				    info[component].name, error_severity[severity]);

	drm_ras_counter_put(idx);
}

/**
 * xe_drm_ras_init() - Initialize DRM RAS
 * @xe: xe device instance
 *
 * Allocate and register DRM RAS nodes per device
 *
 * Return: 0 on success, negative error code otherwise.
 */
int xe_drm_ras_init(struct xe_device *xe)
{
	struct xe_drm_ras *ras = &xe->ras.nl_data;
	struct drm_ras_node *node;
	int err;

	if (!xe->info.has_drm_ras)
		return 0;

	node = drmm_kcalloc(&xe->drm, DRM_XE_RAS_ERR_SEV_MAX, sizeof(*node), GFP_KERNEL);
	if (!node)
		return -ENOMEM;

	ras->node = node;

	err = register_nodes(xe);
	if (err) {
		drm_err(&xe->drm, "Failed to register DRM RAS nodes (%pe)\n", ERR_PTR(err));
		return err;
	}

	return 0;
}
