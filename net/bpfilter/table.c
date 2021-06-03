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

static int rule_offset_comparator(const void *x, const void *y)
{
	const struct rule *rule = y;

	return x - (const void *)rule->ipt_entry;
}

static struct rule *table_find_rule_by_offset(struct table *table, uint32_t offset)
{
	const struct bpfilter_ipt_entry *key;

	key = table->entries + offset;

	return bsearch(key, table->rules, table->num_rules, sizeof(table->rules[0]),
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

		if ((uintptr_t)ipt_entry % __alignof__(struct bpfilter_ipt_entry))
			return -EINVAL;

		if (table->size < offset + ipt_entry->next_offset)
			return -EINVAL;

		err = init_rule(ctx, ipt_entry, &table->rules[i]);
		if (err)
			return err;

		table->rules[i].ipt_entry = ipt_entry;
		offset += ipt_entry->next_offset;
	}

	if (offset != ipt_replace->size)
		return -EINVAL;

	if (table->num_rules != ipt_replace->num_entries)
		return -EINVAL;

	return 0;
}

static int table_check_hooks(const struct table *table)
{
	uint32_t max_rule_front, max_rule_last;
	bool check = false;
	int i;

	for (i = 0; i < BPFILTER_INET_HOOK_MAX; ++i) {
		if (!(table->valid_hooks & (1 << i)))
			continue;

		if (check) {
			if (table->hook_entry[i] <= max_rule_front)
				return -EINVAL;

			if (table->underflow[i] <= max_rule_last)
				return -EINVAL;
		}

		max_rule_front = table->hook_entry[i];
		max_rule_last = table->underflow[i];
		check = true;
	}

	return 0;
}

static int table_init_hooks(struct table *table, const struct bpfilter_ipt_replace *ipt_replace)
{
	int i;

	for (i = 0; i < BPFILTER_INET_HOOK_MAX; ++i) {
		struct rule *rule_front, *rule_last;
		int verdict;

		if (!(table->valid_hooks & (1 << i)))
			continue;

		rule_front = table_find_rule_by_offset(table, ipt_replace->hook_entry[i]);
		rule_last = table_find_rule_by_offset(table, ipt_replace->underflow[i]);

		if (!rule_front || !rule_last)
			return -EINVAL;

		if (!is_rule_unconditional(rule_last))
			return -EINVAL;

		if (!rule_has_standard_target(rule_last))
			return -EINVAL;

		verdict = standard_target_verdict(rule_last->target.ipt_target);
		if (verdict >= 0)
			return -EINVAL;

		verdict = convert_verdict(verdict);

		if (verdict != BPFILTER_NF_DROP && verdict != BPFILTER_NF_ACCEPT)
			return -EINVAL;

		table->hook_entry[i] = rule_front - table->rules;
		table->underflow[i] = rule_last - table->rules;
	}

	return table_check_hooks(table);
}

static struct rule *next_rule(const struct table *table, struct rule *rule)
{
	const uint32_t i = rule - table->rules;

	if (table->num_rules <= i + 1)
		return ERR_PTR(-EINVAL);

	++rule;
	rule->came_from = i;

	return rule;
}

static struct rule *backtrack_rule(const struct table *table, struct rule *rule)
{
	uint32_t i = rule - table->rules;
	int prev_i;

	do {
		rule->hook_mask ^= (1 << BPFILTER_INET_HOOK_MAX);
		prev_i = i;
		i = rule->came_from;
		rule->came_from = 0;

		if (i == prev_i)
			return NULL;

		rule = &table->rules[i];
	} while (prev_i == i + 1);

	return next_rule(table, rule);
}

static int table_check_chain(struct table *table, uint32_t hook, struct rule *rule)
{
	uint32_t i = rule - table->rules;

	rule->came_from = i;

	for (;;) {
		bool visited;
		int verdict;

		if (!rule)
			return 0;

		if (IS_ERR(rule))
			return PTR_ERR(rule);

		i = rule - table->rules;

		if (table->num_rules <= i)
			return -EINVAL;

		if (rule->hook_mask & (1 << BPFILTER_INET_HOOK_MAX))
			return -EINVAL;

		// already visited
		visited = rule->hook_mask & (1 << hook);
		rule->hook_mask |= (1 << hook) | (1 << BPFILTER_INET_HOOK_MAX);

		if (visited) {
			rule = backtrack_rule(table, rule);
			continue;
		}

		if (!rule_has_standard_target(rule)) {
			rule = next_rule(table, rule);
			continue;
		}

		verdict = standard_target_verdict(rule->target.ipt_target);
		if (verdict > 0) {
			rule = table_find_rule_by_offset(table, verdict);
			if (!rule)
				return -EINVAL;

			rule->came_from = i;
			continue;
		}

		if (!is_rule_unconditional(rule)) {
			rule = next_rule(table, rule);
			continue;
		}

		rule = backtrack_rule(table, rule);
	}

	return 0;
}

static int table_check_chains(struct table *table)
{
	int i, err;

	for (i = 0, err = 0; !err && i < BPFILTER_INET_HOOK_MAX; ++i) {
		if (table->valid_hooks & (1 << i))
			err = table_check_chain(table, i, &table->rules[table->hook_entry[i]]);
	}

	return err;
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

	err = table_check_chains(table);
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
		const struct rule *rule_front, *rule_last;

		if (!(table->valid_hooks & (1 << i))) {
			info->hook_entry[i] = 0;
			info->underflow[i] = 0;
			continue;
		}

		rule_front = &table->rules[table->hook_entry[i]];
		rule_last = &table->rules[table->underflow[i]];
		info->hook_entry[i] = (const void *)rule_front->ipt_entry - table->entries;
		info->underflow[i] = (const void *)rule_last->ipt_entry - table->entries;
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
