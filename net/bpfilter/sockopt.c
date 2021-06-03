// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021 Telegram FZ-LLC
 */

#define _GNU_SOURCE

#include "sockopt.h"

#include <linux/err.h>
#include <linux/list.h>

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>

#include "context.h"
#include "map-common.h"
#include "match.h"
#include "msgfmt.h"

static int pvm_read(pid_t pid, void *to, const void *from, size_t count)
{
	const struct iovec l_iov = { .iov_base = to, .iov_len = count };
	const struct iovec r_iov = { .iov_base = (void *)from, .iov_len = count };
	ssize_t total_bytes;

	total_bytes = process_vm_readv(pid, &l_iov, 1, &r_iov, 1, 0);
	if (total_bytes == -1)
		return -errno;

	if (total_bytes != count)
		return -EFAULT;

	return 0;
}

static int pvm_read_from_offset(pid_t pid, void *to, const void *from, size_t offset, size_t count)
{
	return pvm_read(pid, to + offset, from + offset, count);
}

static int pvm_write(pid_t pid, void *to, const void *from, size_t count)
{
	const struct iovec l_iov = { .iov_base = (void *)from, .iov_len = count };
	const struct iovec r_iov = { .iov_base = to, .iov_len = count };
	ssize_t total_bytes;

	total_bytes = process_vm_writev(pid, &l_iov, 1, &r_iov, 1, 0);
	if (total_bytes == -1)
		return -errno;

	if (total_bytes != count)
		return -EFAULT;

	return 0;
}

static int read_ipt_get_info(const struct mbox_request *req, struct bpfilter_ipt_get_info *info)
{
	int err;

	if (req->len != sizeof(*info))
		return -EINVAL;

	err = pvm_read(req->pid, info, (const void *)req->addr, sizeof(*info));
	if (err)
		return err;

	info->name[sizeof(info->name) - 1] = '\0';

	return 0;
}

static int sockopt_get_info(struct context *ctx, const struct mbox_request *req)
{
	struct bpfilter_ipt_get_info info;
	struct table *table;
	int err;

	BFLOG_DEBUG(ctx, "handling IPT_SO_GET_INFO\n");

	if (req->len != sizeof(info))
		return -EINVAL;

	err = read_ipt_get_info(req, &info);
	if (err) {
		BFLOG_DEBUG(ctx, "cannot read ipt_get_info: %s\n", strerror(-err));
		return err;
	}

	table = map_find(&ctx->table_index.map, info.name);
	if (IS_ERR(table)) {
		BFLOG_DEBUG(ctx, "cannot find table: '%s'\n", info.name);
		return -ENOENT;
	}

	table_get_info(table, &info);

	return pvm_write(req->pid, (void *)req->addr, &info, sizeof(info));
}

static int read_ipt_get_entries(const struct mbox_request *req,
				struct bpfilter_ipt_get_entries *entries)
{
	int err;

	if (req->len < sizeof(*entries))
		return -EINVAL;

	err = pvm_read(req->pid, entries, (const void *)req->addr, sizeof(*entries));
	if (err)
		return err;

	entries->name[sizeof(entries->name) - 1] = '\0';

	return 0;
}

static int sockopt_get_entries(struct context *ctx, const struct mbox_request *req)
{
	struct bpfilter_ipt_get_entries get_entries, *entries;
	struct table *table;
	int err;

	BFLOG_DEBUG(ctx, "handling IPT_SO_GET_ENTRIES\n");

	err = read_ipt_get_entries(req, &get_entries);
	if (err) {
		BFLOG_DEBUG(ctx, "cannot read ipt_get_entries: %s\n", strerror(-err));
		return err;
	}

	table = map_find(&ctx->table_index.map, get_entries.name);
	if (IS_ERR(table)) {
		BFLOG_DEBUG(ctx, "cannot find table: '%s'\n", get_entries.name);
		return -ENOENT;
	}

	if (get_entries.size != table->size) {
		BFLOG_DEBUG(ctx, "table '%s' get entries size mismatch\n", get_entries.name);
		return -EINVAL;
	}

	entries = (struct bpfilter_ipt_get_entries *)req->addr;

	err = pvm_write(req->pid, entries->name, table->name, sizeof(entries->name));
	if (err)
		return err;

	err = pvm_write(req->pid, &entries->size, &table->size, sizeof(table->size));
	if (err)
		return err;

	return pvm_write(req->pid, entries->entries, table->entries, table->size);
}

static int read_ipt_get_revision(const struct mbox_request *req,
				 struct bpfilter_ipt_get_revision *revision)
{
	int err;

	if (req->len != sizeof(*revision))
		return -EINVAL;

	err = pvm_read(req->pid, revision, (const void *)req->addr, sizeof(*revision));
	if (err)
		return err;

	revision->name[sizeof(revision->name) - 1] = '\0';

	return 0;
}

static int sockopt_get_revision_match(struct context *ctx, const struct mbox_request *req)
{
	struct bpfilter_ipt_get_revision get_revision;
	const struct match_ops *found;
	int err;

	BFLOG_DEBUG(ctx, "handling IPT_SO_GET_REVISION_MATCH\n");

	err = read_ipt_get_revision(req, &get_revision);
	if (err)
		return err;

	found = map_find(&ctx->match_ops_map, get_revision.name);
	if (IS_ERR(found)) {
		BFLOG_DEBUG(ctx, "cannot find match: '%s'\n", get_revision.name);
		return PTR_ERR(found);
	}

	return found->revision;
}

static int sockopt_get_revision_target(struct context *ctx, const struct mbox_request *req)
{
	struct bpfilter_ipt_get_revision get_revision;
	const struct match_ops *found;
	int err;

	BFLOG_DEBUG(ctx, "handling IPT_SO_GET_REVISION_TARGET\n");

	err = read_ipt_get_revision(req, &get_revision);
	if (err)
		return err;

	found = map_find(&ctx->target_ops_map, get_revision.name);
	if (IS_ERR(found)) {
		BFLOG_DEBUG(ctx, "cannot find target: '%s'\n", get_revision.name);
		return PTR_ERR(found);
	}

	return found->revision;
}

static struct bpfilter_ipt_replace *read_ipt_replace(const struct mbox_request *req)
{
	struct bpfilter_ipt_replace ipt_header, *ipt_replace;
	int err;

	if (req->len < sizeof(ipt_header))
		return ERR_PTR(-EINVAL);

	err = pvm_read(req->pid, &ipt_header, (const void *)req->addr, sizeof(ipt_header));
	if (err)
		return ERR_PTR(err);

	if (ipt_header.num_counters == 0)
		return ERR_PTR(-EINVAL);

	if (ipt_header.num_counters >= INT_MAX / sizeof(struct bpfilter_ipt_counters))
		return ERR_PTR(-ENOMEM);

	ipt_header.name[sizeof(ipt_header.name) - 1] = '\0';

	ipt_replace = malloc(sizeof(ipt_header) + ipt_header.size);
	if (!ipt_replace)
		return ERR_PTR(-ENOMEM);

	memcpy(ipt_replace, &ipt_header, sizeof(ipt_header));

	err = pvm_read_from_offset(req->pid, ipt_replace, (const void *)req->addr,
				   sizeof(ipt_header), ipt_header.size);
	if (err) {
		free(ipt_replace);
		return ERR_PTR(err);
	}

	return ipt_replace;
}

static int sockopt_set_replace(struct context *ctx, const struct mbox_request *req)
{
	struct bpfilter_ipt_replace *ipt_replace;
	struct table *table, *new_table = NULL;
	int err;

	BFLOG_DEBUG(ctx, "handling IPT_SO_SET_REPLACE\n");

	ipt_replace = read_ipt_replace(req);
	if (IS_ERR(ipt_replace)) {
		BFLOG_DEBUG(ctx, "cannot read ipt_replace: %s\n", strerror(-PTR_ERR(ipt_replace)));
		return PTR_ERR(ipt_replace);
	}

	table = map_find(&ctx->table_index.map, ipt_replace->name);
	if (IS_ERR(table)) {
		err = PTR_ERR(table);
		BFLOG_DEBUG(ctx, "cannot find table: '%s'\n", ipt_replace->name);
		goto cleanup;
	}

	new_table = create_table(ctx, ipt_replace);
	if (IS_ERR(new_table)) {
		err = PTR_ERR(new_table);
		BFLOG_DEBUG(ctx, "cannot read table: %s\n", strerror(-PTR_ERR(new_table)));
		goto cleanup;
	}

	// Here be codegen
	// ...
	//

	err = map_update(&ctx->table_index.map, new_table->name, new_table);
	if (err) {
		BFLOG_DEBUG(ctx, "cannot update table map: %s\n", strerror(-err));
		goto cleanup;
	}

	list_add_tail(&new_table->list, &ctx->table_index.list);
	new_table = table;

cleanup:
	if (!IS_ERR(new_table))
		free_table(new_table);

	free(ipt_replace);

	return err;
}

static struct bpfilter_ipt_counters_info *read_ipt_counters_info(const struct mbox_request *req)
{
	struct bpfilter_ipt_counters_info *info;
	size_t size;
	int err;

	if (req->len < sizeof(*info))
		return ERR_PTR(-EINVAL);

	info = malloc(req->len);
	if (!info)
		return ERR_PTR(-ENOMEM);

	err = pvm_read(req->pid, info, (const void *)req->addr, sizeof(*info));
	if (err)
		goto err_free;

	size = info->num_counters * sizeof(info->counters[0]);
	if (req->len != sizeof(*info) + size) {
		err = -EINVAL;
		goto err_free;
	}

	info->name[sizeof(info->name) - 1] = '\0';

	err = pvm_read_from_offset(req->pid, info, (const void *)req->addr, sizeof(*info), size);
	if (err)
		goto err_free;

	return info;

err_free:
	free(info);

	return ERR_PTR(err);
}

static int sockopt_set_add_counters(struct context *ctx, const struct mbox_request *req)
{
	struct bpfilter_ipt_counters_info *info;
	struct table *table;
	int err = 0;

	BFLOG_DEBUG(ctx, "handling IPT_SO_SET_ADD_COUNTERS\n");

	info = read_ipt_counters_info(req);
	if (IS_ERR(info)) {
		err = PTR_ERR(info);
		BFLOG_DEBUG(ctx, "cannot read ipt_counters_info: %s\n", strerror(-err));
		goto err_free;
	}

	table = map_find(&ctx->table_index.map, info->name);
	if (IS_ERR(table)) {
		err = PTR_ERR(table);
		BFLOG_DEBUG(ctx, "cannot find table: '%s'\n", info->name);
		goto err_free;
	}

	// TODO handle counters

err_free:
	free(info);

	return err;
}

static int handle_get_request(struct context *ctx, const struct mbox_request *req)
{
	switch (req->cmd) {
	case 0:
		return 0;
	case BPFILTER_IPT_SO_GET_INFO:
		return sockopt_get_info(ctx, req);
	case BPFILTER_IPT_SO_GET_ENTRIES:
		return sockopt_get_entries(ctx, req);
	case BPFILTER_IPT_SO_GET_REVISION_MATCH:
		return sockopt_get_revision_match(ctx, req);
	case BPFILTER_IPT_SO_GET_REVISION_TARGET:
		return sockopt_get_revision_target(ctx, req);
	}

	BFLOG_NOTICE(ctx, "Unexpected SO_GET request: %d\n", req->cmd);

	return -ENOPROTOOPT;
}

static int handle_set_request(struct context *ctx, const struct mbox_request *req)
{
	switch (req->cmd) {
	case BPFILTER_IPT_SO_SET_REPLACE:
		return sockopt_set_replace(ctx, req);
	case BPFILTER_IPT_SO_SET_ADD_COUNTERS:
		return sockopt_set_add_counters(ctx, req);
	}

	BFLOG_NOTICE(ctx, "Unexpected SO_SET request: %d\n", req->cmd);

	return -ENOPROTOOPT;
}

int handle_sockopt_request(struct context *ctx, const struct mbox_request *req)
{
	return req->is_set ? handle_set_request(ctx, req) : handle_get_request(ctx, req);
}
