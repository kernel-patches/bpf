// SPDX-License-Identifier: MIT
/*
 * Copyright © 2026 Intel Corporation
 */

#include <linux/completion.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/netlink.h>
#include <linux/refcount.h>
#include <linux/xarray.h>
#include <net/genetlink.h>

#include <drm/drm_ras.h>

#include "drm_ras_nl.h"

/**
 * DOC: DRM RAS Node Management
 *
 * This module provides the infrastructure to manage RAS (Reliability,
 * Availability, and Serviceability) nodes for DRM drivers. Each
 * DRM driver may register one or more RAS nodes, which represent
 * logical components capable of reporting error counters and other
 * reliability metrics.
 *
 * The nodes are stored in a global xarray `drm_ras_xa` to allow
 * efficient lookup by ID. Nodes can be registered or unregistered
 * dynamically at runtime.
 *
 * A Generic Netlink family `drm_ras` exposes the below operations to
 * userspace:
 *
 * 1. LIST_NODES: Dump all currently registered RAS nodes.
 *    The user receives an array of node IDs, names, and types.
 *
 * 2. GET_ERROR_COUNTER: Get error counters of a given node.
 *    Userspace must provide Node ID, Error ID (Optional for specific counter).
 *    Returns all counters of a node if only Node ID is provided or specific
 *    error counters.
 *
 * 3. CLEAR_ERROR_COUNTER: Clear error counter of a given node.
 *    Userspace must provide Node ID, Error ID.
 *    Clears specific error counter of a node if supported.
 *
 * 4. ERROR_REPORT: Subscribe to this multicast group to receive error events
 *
 * 5. ERROR_EVENT: Report an error event to userspace. The event contains device, node
 *    and error information that triggered the event.
 *
 * 6. GET_ERROR_THRESHOLD: Query error threshold of a given counter.
 *    Userspace must provide Node ID and Error ID.
 *    Returns the error threshold of a specific counter.
 *
 * 7. SET_ERROR_THRESHOLD: Set error threshold of a given counter.
 *    Userspace must provide Node ID, Error ID and threshold to be set.
 *
 * 8. TELEMETRY_GET: Read a telemetry value.
 *    Userspace must provide Node ID and telemetry field to be read.
 *    Returns the status of the read and the value read (if valid).
 *
 * 9. TELEMETRY_SET: Write a telemetry value.
 *    Userspace must provide Node ID, the telemetry field to write, and the value
 *    to be written.
 *    Returns the status of the write.
 *
 * 10. TELEMETRY_LIST_FIELDS: List the telemetry fields provided by the device.
 *     Each field contains the uAPI defined enum string, its numerical value,
 *     and its mode bitmask, which encodes read/write capabilities.
 *
 * Node registration:
 *
 * - drm_ras_node_register(): Registers a new node and assigns
 *   it a unique ID in the xarray.
 * - drm_ras_node_unregister(): Removes a previously registered
 *   node from the xarray.
 *
 * Node lifetime:
 *
 * The &drm_ras_nl_family uses &genl_family.parallel_ops, so netlink
 * handlers may run concurrently with each other and with
 * drm_ras_node_unregister(). Node memory is owned by the driver, which
 * typically frees it right after drm_ras_node_unregister() returns. To make
 * this safe, every handler looks a node up with drm_ras_node_get(), which
 * takes a reference under the xarray lock, and drops it with
 * drm_ras_node_put() once it is done touching the node. A node holds one
 * reference for being registered; drm_ras_node_unregister() removes the node
 * from the xarray (so no new lookups can find it), drops that registration
 * reference, and then waits for any in-flight handlers to drop theirs before
 * returning. The driver may therefore free the node as soon as
 * drm_ras_node_unregister() returns.
 *
 * Node type:
 *
 * - ERROR_COUNTER:
 *     + The driver must implement the query_error_counter() callback to provide
 *       the name and the value of the error counter.
 *     + The driver must provide a error_counter_range.last value informing the
 *       last valid error ID.
 *     + The driver can provide a error_counter_range.first value informing the
 *       first valid error ID.
 *     + The error counters in the driver doesn't need to be contiguous, but the
 *       driver must return -ENOENT to the query_error_counter as an indication
 *       that the ID should be skipped and not listed in the netlink API.
 *     + The driver can optionally implement query_error_threshold() and
 *       set_error_threshold() callbacks to facilitate getting/setting error
 *       threshold of the counter. Threshold in RAS context means the number of
 *       errors the hardware is expected to accumulate before it raises them to
 *       software. This is to have a fine grained control over error notifications
 *       that are raised by the hardware.
 *     + The driver is responsible for error threshold bounds checking.
 *
 * - TELEMETRY:
 *     + The driver must implement the telemetry_get() callbacks, telemetry_set()
 *       is optional.
 *     + The driver must provide a list of telemetry fields corresponding to
 *       their uAPI definitions and values, with each field's supported access
 *       modes (read/write) encoded in its mode bitmask. Fields writable via
 *       telemetry_set() must have the write mode bit set.
 *     + The driver can optionally provide a pre_doit callback, telemetry_pre(),
 *       to enforce permissions checks on telemetry operations.
 *
 * Netlink handlers:
 *
 * - drm_ras_nl_list_nodes_dumpit(): Implements the LIST_NODES
 *   operation, iterating over the xarray.
 * - drm_ras_nl_get_error_counter_dumpit(): Implements the GET_ERROR_COUNTER dumpit
 *   operation, fetching all counters from a specific node.
 * - drm_ras_nl_get_error_counter_doit(): Implements the GET_ERROR_COUNTER doit
 *   operation, fetching a counter value from a specific node.
 * - drm_ras_nl_clear_error_counter_doit(): Implements the CLEAR_ERROR_COUNTER doit
 *   operation, clearing a counter value from a specific node.
 * - drm_ras_nl_get_error_threshold_doit(): Implements the GET_ERROR_THRESHOLD doit
 *   operation, fetching the error threshold of a specific counter.
 * - drm_ras_nl_set_error_threshold_doit(): Implements the SET_ERROR_THRESHOLD doit
 *   operation, setting the error threshold of a specific counter.
 * - drm_ras_nl_pre_telemetry(): TELEMETRY_GET and TELEMETRY_SET pre_doit
 *   operation. Looks the node up, takes a reference on it and stashes it in
 *   info->ctx, and enforces the node's optional permission check.
 * - drm_ras_nl_post_telemetry(): TELEMETRY_GET and TELEMETRY_SET post_doit
 *   operation, dropping the reference taken by drm_ras_nl_pre_telemetry().
 * - drm_ras_nl_telemetry_get_doit(): Implements the TELEMETRY_GET doit operation,
 *   invoking the driver's telemetry_get callback and returning the results.
 * - drm_ras_nl_telemetry_set_doit(): Implements the TELEMETRY_SET doit operation,
 *   invoking the driver's telemetry_set callback and returning the results.
 * - drm_ras_nl_telemetry_list_fields_dumpit(): Implements the TELEMETRY_LIST_FIELDS
 *   dumpit operation, enumerating all telemetry fields and their supported
 *   access modes for a telemetry node.
 */

static DEFINE_XARRAY_ALLOC(drm_ras_xa);

/*
 * Per-command netlink context. Overlaid on the callback storage (cb->ctx) for
 * dumps and on genl_info (info->ctx) for doits. @node pins the node targeted by
 * a telemetry get/set doit between its pre_doit and post_doit. Dumps never
 * hold a node reference across dumpit() calls.
 */
struct drm_ras_ctx {
	/* Which xarray id, error id, or field id to restart the dump from */
	unsigned long restart;
	/* Node targeted by a telemetry get/set doit */
	struct drm_ras_node *node;
};

static_assert(sizeof(struct drm_ras_ctx) <= NETLINK_CTX_SIZE);

/**
 * drm_ras_node_get() - Look up a RAS node by ID and take a reference
 * @node_id: ID of the node to look up
 *
 * Looks the node up in the global xarray and, if found, takes a reference to
 * it so that it cannot be freed while the caller is using it. The lookup and
 * the reference bump happen under the xarray lock, which serialises them
 * against the xa_erase() in drm_ras_node_unregister(): a node that is still
 * present in the xarray is guaranteed to still hold its registration
 * reference, so the bump can never operate on freed memory.
 *
 * The caller must drop the returned reference with drm_ras_node_put().
 *
 * Return: the referenced node, or NULL if no node with @node_id is registered.
 */
static struct drm_ras_node *drm_ras_node_get(u32 node_id)
{
	struct drm_ras_node *node;

	xa_lock(&drm_ras_xa);
	node = xa_load(&drm_ras_xa, node_id);
	if (node)
		refcount_inc(&node->ref);
	xa_unlock(&drm_ras_xa);

	return node;
}

/**
 * drm_ras_node_get_next() - Take a reference on the next registered RAS node
 * @next: in/out cursor; on entry the first ID to consider, on return the ID of
 *        the node whose reference was taken
 *
 * Iterator counterpart of drm_ras_node_get() used by the LIST_NODES dump.
 * Finds the first node with an ID at or above *@next, takes a reference to it
 * under the xarray lock and reports its ID back in *@next.
 *
 * The caller must drop the returned reference with drm_ras_node_put().
 *
 * Return: the referenced node, or NULL if no further node is registered.
 */
static struct drm_ras_node *drm_ras_node_get_next(unsigned long *next)
{
	struct drm_ras_node *node;

	xa_lock(&drm_ras_xa);
	node = xa_find(&drm_ras_xa, next, ULONG_MAX, XA_PRESENT);
	if (node)
		refcount_inc(&node->ref);
	xa_unlock(&drm_ras_xa);

	return node;
}

/**
 * drm_ras_node_put() - Drop a reference taken on a RAS node
 * @node: node to drop a reference on, may be NULL
 *
 * Drops a reference previously taken by drm_ras_node_get() or
 * drm_ras_node_get_next(). When the last reference (including the registration
 * reference dropped by drm_ras_node_unregister()) goes away, the waiter in
 * drm_ras_node_unregister() is woken so the driver can free the node.
 */
static void drm_ras_node_put(struct drm_ras_node *node)
{
	if (node && refcount_dec_and_test(&node->ref))
		complete(&node->unregistered);
}

/**
 * drm_ras_nl_list_nodes_dumpit() - Dump all registered RAS nodes
 * @skb: Netlink message buffer
 * @cb: Callback context for multi-part dumps
 *
 * Iterates over all registered RAS nodes in the global xarray and appends
 * their attributes (ID, name, type) to the given netlink message buffer.
 * Uses @cb->ctx to track progress in case the message buffer fills up, allowing
 * multi-part dump support. On buffer overflow, updates the context to resume
 * from the last node on the next invocation.
 *
 * Return: 0 if all nodes fit in @skb, number of bytes added to @skb if
 *          the buffer filled up (requires multi-part continuation), or
 *          a negative error code on failure.
 */
int drm_ras_nl_list_nodes_dumpit(struct sk_buff *skb,
				 struct netlink_callback *cb)
{
	const struct genl_info *info = genl_info_dump(cb);
	struct drm_ras_ctx *ctx = (void *)cb->ctx;
	unsigned long id = ctx->restart;
	struct drm_ras_node *node;
	struct nlattr *hdr;
	int ret = 0;

	while ((node = drm_ras_node_get_next(&id))) {
		hdr = genlmsg_iput(skb, info);
		if (!hdr) {
			ret = -EMSGSIZE;
			drm_ras_node_put(node);
			break;
		}

		ret = nla_put_u32(skb, DRM_RAS_A_NODE_ATTRS_NODE_ID, node->id);
		if (ret)
			goto cancel;

		ret = nla_put_string(skb, DRM_RAS_A_NODE_ATTRS_DEVICE_NAME,
				     node->device_name);
		if (ret)
			goto cancel;

		ret = nla_put_string(skb, DRM_RAS_A_NODE_ATTRS_NODE_NAME,
				     node->node_name);
		if (ret)
			goto cancel;

		ret = nla_put_u32(skb, DRM_RAS_A_NODE_ATTRS_NODE_TYPE,
				  node->type);
		if (ret)
			goto cancel;

		genlmsg_end(skb, hdr);
		drm_ras_node_put(node);
		id++;
		continue;

cancel:
		genlmsg_cancel(skb, hdr);
		drm_ras_node_put(node);
		break;
	}

	if (ret == -EMSGSIZE)
		ctx->restart = id;

	return ret;
}

static int get_node_error_counter(struct drm_ras_node *node, u32 error_id,
				  const char **name, u32 *value)
{
	if (!node->query_error_counter)
		return -ENOENT;

	if (error_id < node->error_counter_range.first ||
	    error_id > node->error_counter_range.last)
		return -EINVAL;

	return node->query_error_counter(node, error_id, name, value);
}

static int get_node_error_threshold(struct drm_ras_node *node, u32 error_id,
				    const char **name, u32 *threshold)
{
	if (!node->query_error_threshold)
		return -EOPNOTSUPP;

	if (error_id < node->error_counter_range.first || error_id > node->error_counter_range.last)
		return -EINVAL;

	return node->query_error_threshold(node, error_id, name, threshold);
}

static int set_node_error_threshold(struct drm_ras_node *node, u32 error_id, u32 threshold)
{
	if (!node->set_error_threshold)
		return -EOPNOTSUPP;

	if (error_id < node->error_counter_range.first || error_id > node->error_counter_range.last)
		return -EINVAL;

	return node->set_error_threshold(node, error_id, threshold);
}

static int msg_reply_value(struct sk_buff *msg, u32 error_id,
			   const char *error_name, u32 value)
{
	int ret;

	ret = nla_put_u32(msg, DRM_RAS_A_ERROR_COUNTER_ATTRS_ERROR_ID, error_id);
	if (ret)
		return ret;

	ret = nla_put_string(msg, DRM_RAS_A_ERROR_COUNTER_ATTRS_ERROR_NAME,
			     error_name);
	if (ret)
		return ret;

	return nla_put_u32(msg, DRM_RAS_A_ERROR_COUNTER_ATTRS_ERROR_VALUE,
			   value);
}

static int msg_put_error_event_attrs(struct sk_buff *msg, struct drm_ras_node *node,
				     u32 error_id, const char *error_name, u32 value)
{
	int ret;

	ret = nla_put_string(msg, DRM_RAS_A_ERROR_EVENT_ATTRS_DEVICE_NAME, node->device_name);
	if (ret)
		return ret;

	ret = nla_put_u32(msg, DRM_RAS_A_ERROR_EVENT_ATTRS_NODE_ID, node->id);
	if (ret)
		return ret;

	ret = nla_put_string(msg, DRM_RAS_A_ERROR_EVENT_ATTRS_NODE_NAME, node->node_name);
	if (ret)
		return ret;

	ret = nla_put_u32(msg, DRM_RAS_A_ERROR_EVENT_ATTRS_ERROR_ID, error_id);
	if (ret)
		return ret;

	ret = nla_put_string(msg, DRM_RAS_A_ERROR_EVENT_ATTRS_ERROR_NAME, error_name);
	if (ret)
		return ret;

	return nla_put_u32(msg, DRM_RAS_A_ERROR_EVENT_ATTRS_ERROR_VALUE, value);
}

static int msg_reply_threshold(struct sk_buff *msg, u32 error_id, const char *error_name,
			       u32 threshold)
{
	int ret;

	ret = nla_put_u32(msg, DRM_RAS_A_ERROR_COUNTER_ATTRS_ERROR_ID, error_id);
	if (ret)
		return ret;

	ret = nla_put_string(msg, DRM_RAS_A_ERROR_COUNTER_ATTRS_ERROR_NAME, error_name);
	if (ret)
		return ret;

	return nla_put_u32(msg, DRM_RAS_A_ERROR_COUNTER_ATTRS_ERROR_THRESHOLD, threshold);
}

static int doit_reply_value(struct genl_info *info, u32 node_id,
			    u32 error_id)
{
	struct drm_ras_node *node;
	struct sk_buff *msg;
	struct nlattr *hdr;
	const char *error_name;
	u32 value;
	int ret;

	node = drm_ras_node_get(node_id);
	if (!node)
		return -ENOENT;

	msg = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!msg) {
		ret = -ENOMEM;
		goto put_node;
	}

	hdr = genlmsg_iput(msg, info);
	if (!hdr) {
		ret = -EMSGSIZE;
		goto free_msg;
	}

	ret = get_node_error_counter(node, error_id,
				     &error_name, &value);
	if (ret)
		goto cancel_msg;

	ret = msg_reply_value(msg, error_id, error_name, value);
	if (ret)
		goto cancel_msg;

	genlmsg_end(msg, hdr);

	drm_ras_node_put(node);

	return genlmsg_reply(msg, info);

cancel_msg:
	genlmsg_cancel(msg, hdr);
free_msg:
	nlmsg_free(msg);
put_node:
	drm_ras_node_put(node);
	return ret;
}

static int doit_reply_threshold(struct genl_info *info, u32 node_id, u32 error_id)
{
	struct drm_ras_node *node;
	const char *error_name;
	struct sk_buff *msg;
	struct nlattr *hdr;
	u32 threshold;
	int ret;

	node = drm_ras_node_get(node_id);
	if (!node)
		return -ENOENT;

	msg = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!msg) {
		ret = -ENOMEM;
		goto put_node;
	}

	hdr = genlmsg_iput(msg, info);
	if (!hdr) {
		ret = -EMSGSIZE;
		goto free_msg;
	}

	ret = get_node_error_threshold(node, error_id, &error_name, &threshold);
	if (ret)
		goto cancel_msg;

	ret = msg_reply_threshold(msg, error_id, error_name, threshold);
	if (ret)
		goto cancel_msg;

	genlmsg_end(msg, hdr);

	drm_ras_node_put(node);

	return genlmsg_reply(msg, info);

cancel_msg:
	genlmsg_cancel(msg, hdr);
free_msg:
	nlmsg_free(msg);
put_node:
	drm_ras_node_put(node);
	return ret;
}

/**
 * drm_ras_nl_error_event() - Report an error event
 * @node: Node structure
 * @error_id: ID of the error
 * @error_name: Name of the error
 * @value: Value of the error counter
 *
 * Report an error-event to userspace using the error-report multicast group.
 *
 * The caller owns @node and must guarantee it stays alive for the duration of
 * this call (it is the driver's own node), so no additional reference is taken
 * here.
 *
 * Context: Process context only. Uses %GFP_KERNEL and multicasts to all
 *          netns, which is unbounded work; callers in interrupt handlers
 *          or other atomic context must defer event.
 *
 * Return: 0 on success, or negative errno on failure.
 */
int drm_ras_nl_error_event(struct drm_ras_node *node, u32 error_id, const char *error_name,
			   u32 value)
{
	struct genl_info info;
	struct sk_buff *msg;
	struct nlattr *hdr;
	int ret;

	if (!node || !error_name)
		return -EINVAL;

	/* Check the node is currently registered */
	if (xa_load(&drm_ras_xa, node->id) != node)
		return -ENOENT;

	/* Currently only Error Counter events are supported */
	if (node->type != DRM_RAS_NODE_TYPE_ERROR_COUNTER)
		return -EOPNOTSUPP;

	/* Check the error ID is within the valid range */
	if (error_id < node->error_counter_range.first ||
	    error_id > node->error_counter_range.last)
		return -EINVAL;

	genl_info_init_ntf(&info, &drm_ras_nl_family, DRM_RAS_CMD_ERROR_EVENT);

	msg = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	hdr = genlmsg_iput(msg, &info);
	if (!hdr) {
		ret = -EMSGSIZE;
		goto free_msg;
	}

	ret = msg_put_error_event_attrs(msg, node, error_id, error_name, value);
	if (ret)
		goto cancel_msg;

	genlmsg_end(msg, hdr);
	genlmsg_multicast_allns(&drm_ras_nl_family, msg, 0, DRM_RAS_NLGRP_ERROR_REPORT);

	return 0;

cancel_msg:
	genlmsg_cancel(msg, hdr);
free_msg:
	nlmsg_free(msg);
	return ret;
}
EXPORT_SYMBOL(drm_ras_nl_error_event);

/**
 * drm_ras_nl_get_error_counter_dumpit() - Dump all Error Counters
 * @skb: Netlink message buffer
 * @cb: Callback context for multi-part dumps
 *
 * Iterates over all error counters in a given Node and appends
 * their attributes (ID, name, value) to the given netlink message buffer.
 * Uses @cb->ctx to track progress in case the message buffer fills up, allowing
 * multi-part dump support. On buffer overflow, updates the context to resume
 * from the last node on the next invocation.
 *
 * Return: 0 if all errors fit in @skb, number of bytes added to @skb if
 *          the buffer filled up (requires multi-part continuation), or
 *          a negative error code on failure.
 */
int drm_ras_nl_get_error_counter_dumpit(struct sk_buff *skb,
					struct netlink_callback *cb)
{
	const struct genl_info *info = genl_info_dump(cb);
	struct drm_ras_ctx *ctx = (void *)cb->ctx;
	struct drm_ras_node *node;
	struct nlattr *hdr;
	const char *error_name;
	u32 node_id, error_id, value;
	int ret = 0;

	if (!info->attrs || GENL_REQ_ATTR_CHECK(info, DRM_RAS_A_ERROR_COUNTER_ATTRS_NODE_ID))
		return -EINVAL;

	node_id = nla_get_u32(info->attrs[DRM_RAS_A_ERROR_COUNTER_ATTRS_NODE_ID]);

	node = drm_ras_node_get(node_id);
	if (!node)
		return -ENOENT;

	for (error_id = max(node->error_counter_range.first, ctx->restart);
	     error_id <= node->error_counter_range.last;
	     error_id++) {
		ret = get_node_error_counter(node, error_id,
					     &error_name, &value);
		/*
		 * For non-contiguous range, driver return -ENOENT as indication
		 * to skip this ID when listing all errors.
		 */
		if (ret == -ENOENT)
			continue;
		if (ret)
			break;

		hdr = genlmsg_iput(skb, info);

		if (!hdr) {
			ret = -EMSGSIZE;
			break;
		}

		ret = msg_reply_value(skb, error_id, error_name, value);
		if (ret) {
			genlmsg_cancel(skb, hdr);
			break;
		}

		genlmsg_end(skb, hdr);
	}

	if (ret == -EMSGSIZE)
		ctx->restart = error_id;

	drm_ras_node_put(node);

	return ret;
}

/**
 * drm_ras_nl_get_error_counter_doit() - Query an error counter of an node
 * @skb: Netlink message buffer
 * @info: Generic Netlink info containing attributes of the request
 *
 * Extracts the node ID and error ID from the netlink attributes and
 * retrieves the current value of the corresponding error counter. Sends the
 * result back to the requesting user via the standard Genl reply.
 *
 * Return: 0 on success, or negative errno on failure.
 */
int drm_ras_nl_get_error_counter_doit(struct sk_buff *skb,
				      struct genl_info *info)
{
	u32 node_id, error_id;

	if (!info->attrs ||
	    GENL_REQ_ATTR_CHECK(info, DRM_RAS_A_ERROR_COUNTER_ATTRS_NODE_ID) ||
	    GENL_REQ_ATTR_CHECK(info, DRM_RAS_A_ERROR_COUNTER_ATTRS_ERROR_ID))
		return -EINVAL;

	node_id = nla_get_u32(info->attrs[DRM_RAS_A_ERROR_COUNTER_ATTRS_NODE_ID]);
	error_id = nla_get_u32(info->attrs[DRM_RAS_A_ERROR_COUNTER_ATTRS_ERROR_ID]);

	return doit_reply_value(info, node_id, error_id);
}

/**
 * drm_ras_nl_clear_error_counter_doit() - Clear an error counter of a node
 * @skb: Netlink message buffer
 * @info: Generic Netlink info containing attributes of the request
 *
 * Extracts the node ID and error ID from the netlink attributes and
 * clears the current value.
 *
 * Return: 0 on success, or negative errno on failure.
 */
int drm_ras_nl_clear_error_counter_doit(struct sk_buff *skb,
					struct genl_info *info)
{
	struct drm_ras_node *node;
	u32 node_id, error_id;
	int ret;

	if (!info->attrs ||
	    GENL_REQ_ATTR_CHECK(info, DRM_RAS_A_ERROR_COUNTER_ATTRS_NODE_ID) ||
	    GENL_REQ_ATTR_CHECK(info, DRM_RAS_A_ERROR_COUNTER_ATTRS_ERROR_ID))
		return -EINVAL;

	node_id = nla_get_u32(info->attrs[DRM_RAS_A_ERROR_COUNTER_ATTRS_NODE_ID]);
	error_id = nla_get_u32(info->attrs[DRM_RAS_A_ERROR_COUNTER_ATTRS_ERROR_ID]);

	node = drm_ras_node_get(node_id);
	if (!node || !node->clear_error_counter) {
		drm_ras_node_put(node);
		return -ENOENT;
	}

	if (error_id < node->error_counter_range.first ||
	    error_id > node->error_counter_range.last) {
		drm_ras_node_put(node);
		return -EINVAL;
	}

	ret = node->clear_error_counter(node, error_id);

	drm_ras_node_put(node);

	return ret;
}

/**
 * drm_ras_nl_get_error_threshold_doit() - Query error threshold of a counter
 * @skb: Netlink message buffer
 * @info: Generic Netlink info containing attributes of the request
 *
 * Extracts the Node ID and Error ID from the netlink attributes and retrieves
 * the error threshold of the corresponding counter. Sends the result back to
 * the requesting user via the standard Genl reply.
 *
 * Return: 0 on success, or negative errno on failure.
 */
int drm_ras_nl_get_error_threshold_doit(struct sk_buff *skb, struct genl_info *info)
{
	u32 node_id, error_id;

	if (!info->attrs ||
	    GENL_REQ_ATTR_CHECK(info, DRM_RAS_A_ERROR_COUNTER_ATTRS_NODE_ID) ||
	    GENL_REQ_ATTR_CHECK(info, DRM_RAS_A_ERROR_COUNTER_ATTRS_ERROR_ID))
		return -EINVAL;

	node_id = nla_get_u32(info->attrs[DRM_RAS_A_ERROR_COUNTER_ATTRS_NODE_ID]);
	error_id = nla_get_u32(info->attrs[DRM_RAS_A_ERROR_COUNTER_ATTRS_ERROR_ID]);

	return doit_reply_threshold(info, node_id, error_id);
}

/**
 * drm_ras_nl_set_error_threshold_doit() - Set error threshold of a counter
 * @skb: Netlink message buffer
 * @info: Generic Netlink info containing attributes of the request
 *
 * Extracts the Node ID, Error ID and threshold from the netlink attributes and
 * sets the error threshold of the corresponding counter.
 *
 * Return: 0 on success, or negative errno on failure.
 */
int drm_ras_nl_set_error_threshold_doit(struct sk_buff *skb, struct genl_info *info)
{
	u32 node_id, error_id, threshold;
	struct drm_ras_node *node;
	int ret;

	if (!info->attrs ||
	    GENL_REQ_ATTR_CHECK(info, DRM_RAS_A_ERROR_COUNTER_ATTRS_NODE_ID) ||
	    GENL_REQ_ATTR_CHECK(info, DRM_RAS_A_ERROR_COUNTER_ATTRS_ERROR_ID) ||
	    GENL_REQ_ATTR_CHECK(info, DRM_RAS_A_ERROR_COUNTER_ATTRS_ERROR_THRESHOLD))
		return -EINVAL;

	node_id = nla_get_u32(info->attrs[DRM_RAS_A_ERROR_COUNTER_ATTRS_NODE_ID]);
	error_id = nla_get_u32(info->attrs[DRM_RAS_A_ERROR_COUNTER_ATTRS_ERROR_ID]);
	threshold = nla_get_u32(info->attrs[DRM_RAS_A_ERROR_COUNTER_ATTRS_ERROR_THRESHOLD]);

	node = drm_ras_node_get(node_id);
	if (!node)
		return -ENOENT;

	ret = set_node_error_threshold(node, error_id, threshold);

	drm_ras_node_put(node);

	return ret;
}

/**
 * drm_ras_nl_pre_telemetry - Look up the telemetry node and enforce permissions
 * @ops: Generic netlink operations
 * @skb: Netlink message buffer
 * @info: Generic Netlink info containing attributes of the request
 *
 * Looks up the telemetry node, takes a reference on it with drm_ras_node_get()
 * and stashes it in @info->ctx so the doit handler can use it without a second
 * lookup. The reference is dropped by drm_ras_nl_post_telemetry(), which
 * genetlink only calls when this pre_doit succeeds; every error path here must
 * therefore drop the reference itself. Also enforces the node's optional
 * permission check via the telemetry_pre() callback.
 *
 * Return: 0 on success, or negative errno on failure.
 */
int drm_ras_nl_pre_telemetry(const struct genl_split_ops *ops, struct sk_buff *skb,
			     struct genl_info *info)
{
	struct drm_ras_ctx *ctx = (void *)info->ctx;
	struct drm_ras_node *node;
	u32 node_id;
	int ret;

	if (!info->attrs || GENL_REQ_ATTR_CHECK(info, DRM_RAS_A_TELEMETRY_ATTRS_NODE_ID))
		return -EINVAL;

	node_id = nla_get_u32(info->attrs[DRM_RAS_A_TELEMETRY_ATTRS_NODE_ID]);
	node = drm_ras_node_get(node_id);
	if (!node || node->type != DRM_RAS_NODE_TYPE_TELEMETRY) {
		NL_SET_BAD_ATTR(info->extack, info->attrs[DRM_RAS_A_TELEMETRY_ATTRS_NODE_ID]);
		drm_ras_node_put(node);
		return -ENOENT;
	}

	if (node->telemetry_pre) {
		ret = node->telemetry_pre(node);
		if (ret) {
			drm_ras_node_put(node);
			return ret;
		}
	}

	ctx->node = node;

	return 0;
}

/**
 * drm_ras_nl_post_telemetry - Release the telemetry node after a doit handler
 * @ops: Generic netlink operations
 * @skb: Netlink message buffer
 * @info: Generic Netlink info containing attributes of the request
 *
 * Drops the reference that drm_ras_nl_pre_telemetry() took and stashed in
 * @info->ctx. genetlink only invokes this post_doit when the matching pre_doit
 * succeeded, so ctx->node is always the referenced node here.
 */
void drm_ras_nl_post_telemetry(const struct genl_split_ops *ops, struct sk_buff *skb,
			       struct genl_info *info)
{
	struct drm_ras_ctx *ctx = (void *)info->ctx;

	drm_ras_node_put(ctx->node);
}

static bool telemetry_fields_contains(const struct drm_ras_telemetry_field *fields, u64 value,
				      u32 mode)
{
	unsigned long idx;

	if (!fields)
		return false;

	for (idx = 0; fields[idx].name; idx++) {
		if (fields[idx].value == value && (fields[idx].mode & mode))
			return true;
	}

	return false;
}

/**
 * drm_ras_nl_telemetry_list_fields_dumpit() - Dump a node's telemetry fields.
 * @skb: Netlink message buffer
 * @cb: Callback context for multi-part dumps
 *
 * Displays every telemetry field exposed by the given node, along with
 * each field's supported access modes (read/write).
 *
 * The node reference is taken and dropped within each dumpit() call rather
 * than held across the whole dump, so a userspace dump that is never
 * completed cannot block drm_ras_node_unregister().
 *
 * Return: 0 on success, or negative errno on failure.
 */
int drm_ras_nl_telemetry_list_fields_dumpit(struct sk_buff *skb, struct netlink_callback *cb)
{
	const struct genl_info *info = genl_info_dump(cb);
	struct drm_ras_ctx *ctx = (void *)cb->ctx;
	const struct drm_ras_telemetry_field *field;
	struct drm_ras_node *node;
	struct nlattr *hdr;
	unsigned long idx;
	u32 node_id;
	int ret = 0;

	if (!info->attrs || GENL_REQ_ATTR_CHECK(info, DRM_RAS_A_TELEMETRY_ATTRS_NODE_ID))
		return -EINVAL;

	node_id = nla_get_u32(info->attrs[DRM_RAS_A_TELEMETRY_ATTRS_NODE_ID]);

	node = drm_ras_node_get(node_id);
	if (!node || node->type != DRM_RAS_NODE_TYPE_TELEMETRY) {
		NL_SET_BAD_ATTR(info->extack, info->attrs[DRM_RAS_A_TELEMETRY_ATTRS_NODE_ID]);
		drm_ras_node_put(node);
		return -ENOENT;
	}

	/*
	 * Node IDs may be reused, so the node found here is not necessarily the
	 * one seen by a previous dumpit() call of this dump. Walk the field list
	 * from the start rather than indexing at ctx->restart directly, so a
	 * shorter list can never be read past its terminator.
	 */
	for (idx = 0; node->telemetry_fields[idx].name; idx++) {
		if (idx < ctx->restart)
			continue;

		field = &node->telemetry_fields[idx];

		hdr = genlmsg_iput(skb, info);
		if (!hdr) {
			ret = -EMSGSIZE;
			break;
		}

		ret = nla_put_uint(skb, DRM_RAS_A_TELEMETRY_ATTRS_FIELD, field->value);
		if (ret) {
			genlmsg_cancel(skb, hdr);
			break;
		}

		ret = nla_put_string(skb, DRM_RAS_A_TELEMETRY_ATTRS_FIELD_NAME, field->name);
		if (ret) {
			genlmsg_cancel(skb, hdr);
			break;
		}

		ret = nla_put_uint(skb, DRM_RAS_A_TELEMETRY_ATTRS_MODE, field->mode);
		if (ret) {
			genlmsg_cancel(skb, hdr);
			break;
		}

		genlmsg_end(skb, hdr);
	}

	if (ret == -EMSGSIZE)
		ctx->restart = idx;

	drm_ras_node_put(node);

	return ret;
}

/**
 * drm_ras_nl_telemetry_get_doit() - Query a telemetry value
 * @skb: Netlink message buffer
 * @info: Generic Netlink info containing attributes of the request
 *
 * Extracts the telemetry field from the netlink attributes and
 * reads that value from the device.
 *
 * Return: 0 on success, or negative errno on failure.
 */
int drm_ras_nl_telemetry_get_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drm_ras_ctx *ctx = (void *)info->ctx;
	struct drm_ras_node *node = ctx->node;
	struct sk_buff *msg;
	struct nlattr *hdr;
	u64 field;
	s64 status = 0;
	s64 value = 0;
	int ret = 0;

	if (!info->attrs || GENL_REQ_ATTR_CHECK(info, DRM_RAS_A_TELEMETRY_ATTRS_FIELD))
		return -EINVAL;

	field = nla_get_uint(info->attrs[DRM_RAS_A_TELEMETRY_ATTRS_FIELD]);

	if (!node->telemetry_get) {
		NL_SET_BAD_ATTR(info->extack, info->attrs[DRM_RAS_A_TELEMETRY_ATTRS_NODE_ID]);
		return -ENOENT;
	}

	if (!telemetry_fields_contains(node->telemetry_fields, field,
				       DRM_RAS_TELEMETRY_FIELD_MODE_READ)) {
		NL_SET_BAD_ATTR(info->extack, info->attrs[DRM_RAS_A_TELEMETRY_ATTRS_FIELD]);
		return -EINVAL;
	}

	msg = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	hdr = genlmsg_iput(msg, info);
	if (!hdr) {
		nlmsg_free(msg);
		return -EMSGSIZE;
	}

	ret = node->telemetry_get(node, &field, &value, &status);
	if (ret) {
		nlmsg_free(msg);
		return ret;
	}

	ret = nla_put_sint(msg, DRM_RAS_A_TELEMETRY_ATTRS_STATUS, status);
	if (ret) {
		genlmsg_cancel(msg, hdr);
		nlmsg_free(msg);
		return ret;
	}

	ret = nla_put_sint(msg, DRM_RAS_A_TELEMETRY_ATTRS_VALUE, value);
	if (ret) {
		genlmsg_cancel(msg, hdr);
		nlmsg_free(msg);
		return ret;
	}

	genlmsg_end(msg, hdr);

	return genlmsg_reply(msg, info);
}

/**
 * drm_ras_nl_telemetry_set_doit() - Write a telemetry value
 * @skb: Netlink message buffer
 * @info: Generic Netlink info containing attributes of the request
 *
 * Extracts the telemetry field and value to be written from the netlink
 * attributes and writes that value to the specified field on the device.
 *
 * Return: 0 on success, or negative errno on failure.
 */
int drm_ras_nl_telemetry_set_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drm_ras_ctx *ctx = (void *)info->ctx;
	struct drm_ras_node *node = ctx->node;
	struct sk_buff *msg;
	struct nlattr *hdr;
	u64 field;
	s64 status = 0;
	s64 value = 0;
	int ret = 0;

	if (!info->attrs ||
	    GENL_REQ_ATTR_CHECK(info, DRM_RAS_A_TELEMETRY_ATTRS_VALUE) ||
	    GENL_REQ_ATTR_CHECK(info, DRM_RAS_A_TELEMETRY_ATTRS_FIELD))
		return -EINVAL;

	value = nla_get_sint(info->attrs[DRM_RAS_A_TELEMETRY_ATTRS_VALUE]);
	field = nla_get_uint(info->attrs[DRM_RAS_A_TELEMETRY_ATTRS_FIELD]);

	if (!node->telemetry_set) {
		NL_SET_BAD_ATTR(info->extack, info->attrs[DRM_RAS_A_TELEMETRY_ATTRS_NODE_ID]);
		return -ENOENT;
	}

	if (!telemetry_fields_contains(node->telemetry_fields, field,
				       DRM_RAS_TELEMETRY_FIELD_MODE_WRITE)) {
		NL_SET_BAD_ATTR(info->extack, info->attrs[DRM_RAS_A_TELEMETRY_ATTRS_FIELD]);
		return -EINVAL;
	}

	msg = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	hdr = genlmsg_iput(msg, info);
	if (!hdr) {
		nlmsg_free(msg);
		return -EMSGSIZE;
	}

	ret = node->telemetry_set(node, &field, &value, &status);
	if (ret) {
		nlmsg_free(msg);
		return ret;
	}

	ret = nla_put_sint(msg, DRM_RAS_A_TELEMETRY_ATTRS_STATUS, status);
	if (ret) {
		genlmsg_cancel(msg, hdr);
		nlmsg_free(msg);
		return ret;
	}

	genlmsg_end(msg, hdr);

	return genlmsg_reply(msg, info);
}

/**
 * drm_ras_node_register() - Register a new RAS node
 * @node: Node structure to register
 *
 * Adds the given RAS node to the global node xarray and assigns it
 * a unique ID. Both @node->name and @node->type must be valid.
 *
 * Return: 0 on success, or negative errno on failure:
 */
int drm_ras_node_register(struct drm_ras_node *node)
{
	if (!node->device_name || !node->node_name)
		return -EINVAL;

	/* Currently, only Error Counter and Telemetry endpoints are supported */
	switch (node->type) {
	case DRM_RAS_NODE_TYPE_ERROR_COUNTER:
		/* Mandatory entries for Error Counter Node */
		if (!node->error_counter_range.last || !node->query_error_counter)
			return -EINVAL;
		break;
	case DRM_RAS_NODE_TYPE_TELEMETRY:
		/* Must provide telemetry_get, telemetry_set is optional */
		if (!node->telemetry_get || !node->telemetry_fields)
			return -EINVAL;
		break;
	default:
		return -EINVAL;
	}

	/* One reference is held for being registered in the xarray */
	refcount_set(&node->ref, 1);
	init_completion(&node->unregistered);

	return xa_alloc(&drm_ras_xa, &node->id, node, xa_limit_32b, GFP_KERNEL);
}
EXPORT_SYMBOL(drm_ras_node_register);

/**
 * drm_ras_node_unregister() - Unregister a previously registered node
 * @node: Node structure to unregister
 *
 * Removes the given node from the global node xarray using its ID and waits
 * for any netlink handler that may still be using it to finish. Once this
 * returns, no handler holds a reference to @node and the caller may free it.
 */
void drm_ras_node_unregister(struct drm_ras_node *node)
{
	/* Remove from the xarray so no new lookup can find the node */
	xa_erase(&drm_ras_xa, node->id);

	/* Drop the registration reference and wait for in-flight handlers */
	drm_ras_node_put(node);
	wait_for_completion(&node->unregistered);
}
EXPORT_SYMBOL(drm_ras_node_unregister);
