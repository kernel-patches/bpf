// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021 Telegram FZ-LLC
 */

#define _GNU_SOURCE

#include "table.h"

#include <linux/err.h>
#include <linux/list.h>

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "context.h"
#include "rule.h"
#include "table-map.h"

static int rule_offset_comparator(const void *x, const void *y)
{
	const struct rule *rule = y;
	const uint32_t *offset = x;

	return *offset < rule->offset ? -1 : *offset - rule->offset;
}

static struct rule *table_get_rule_by_offset(struct table *table, uint32_t offset)
{
	return bsearch(&offset, table->rules, table->num_rules, sizeof(table->rules[0]),
		       rule_offset_comparator);
}

static int table_init_rules(struct context *ctx, struct table *table,
			    const struct bpfilter_ipt_replace *ipt_replace)
{
	uint32_t offset;
	int i;

	table->entries = malloc(table->size);
	if (!table->entries)
		return -ENOMEM;

	memcpy(table->entries, ipt_replace->entries, table->size);

	table->rules = calloc(table->num_rules, sizeof(table->rules[0]));
	if (!table->rules)
		return -ENOMEM;

	offset = 0;
	for (i = 0; i < table->num_rules; ++i) {
		const struct bpfilter_ipt_entry *ipt_entry;
		int err;

		if (table->size < offset)
			return -EINVAL;

		if (table->size < offset + sizeof(*ipt_entry))
			return -EINVAL;

		ipt_entry = table->entries + offset;

		if (table->size < offset + ipt_entry->next_offset)
			return -EINVAL;

		err = init_rule(ctx, ipt_entry, &table->rules[i]);
		if (err)
			return err;

		table->rules[i].offset = offset;
		offset += ipt_entry->next_offset;
	}

	if (offset != ipt_replace->size)
		return -EINVAL;

	return 0;
}

static int table_init_hooks(struct table *table, const struct bpfilter_ipt_replace *ipt_replace)
{
	int i;

	for (i = 0; i < BPFILTER_INET_HOOK_MAX; ++i) {
		if (!(table->valid_hooks & (1 << i)))
			continue;

		table->hook_entry[i] = table_get_rule_by_offset(table, ipt_replace->hook_entry[i]);
		table->underflow[i] = table_get_rule_by_offset(table, ipt_replace->underflow[i]);

		if (!table->hook_entry[i] || !table->underflow[i])
			return -EINVAL;
	}

	return 0;
}

struct table *create_table(struct context *ctx, const struct bpfilter_ipt_replace *ipt_replace)
{
	struct table *table;
	int err;

	table = calloc(1, sizeof(*table));
	if (!table)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&table->list);
	snprintf(table->name, sizeof(table->name), "%s", ipt_replace->name);
	table->valid_hooks = ipt_replace->valid_hooks;
	table->num_rules = ipt_replace->num_entries;
	table->num_counters = ipt_replace->num_counters;
	table->size = ipt_replace->size;

	err = table_init_rules(ctx, table, ipt_replace);
	if (err)
		goto err_free;

	err = table_init_hooks(table, ipt_replace);
	if (err)
		goto err_free;

	return table;

err_free:
	free_table(table);

	return ERR_PTR(err);
}

void table_get_info(const struct table *table, struct bpfilter_ipt_get_info *info)
{
	int i;

	snprintf(info->name, sizeof(info->name), "%s", table->name);
	info->valid_hooks = table->valid_hooks;
	for (i = 0; i < BPFILTER_INET_HOOK_MAX; ++i) {
		const struct rule *hook_entry = table->hook_entry[i];
		const struct rule *underflow = table->underflow[i];

		info->hook_entry[i] = hook_entry ? hook_entry->offset : 0;
		info->underflow[i] = underflow ? underflow->offset : 0;
	}
	info->num_entries = table->num_rules;
	info->size = table->size;
}

void free_table(struct table *table)
{
	int i;

	if (!table)
		return;

	list_del(&table->list);

	if (table->rules) {
		for (i = 0; i < table->num_rules; ++i)
			free_rule(&table->rules[i]);
		free(table->rules);
	}

	free(table->entries);
	free(table);
}
