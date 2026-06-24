// SPDX-License-Identifier: GPL-2.0

#include <linux/err.h>
#include <string.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <linux/btf.h>
#include <linux/kernel.h>
#define CONFIG_DEBUG_INFO_BTF
#include <linux/btf_ids.h>
#include "test_progs.h"

#define BTF_DATA_FILE "resolve_btfids.test.o.BTF"

struct symbol {
	const char	*name;
	int		 type;
	int		 id;
};

struct symbol test_symbols[] = {
	{ "unused",  BTF_KIND_UNKN,     0 },
	{ "S",       BTF_KIND_TYPEDEF, -1 },
	{ "T",       BTF_KIND_TYPEDEF, -1 },
	{ "U",       BTF_KIND_TYPEDEF, -1 },
	{ "S",       BTF_KIND_STRUCT,  -1 },
	{ "U",       BTF_KIND_UNION,   -1 },
	{ "func",    BTF_KIND_FUNC,    -1 },
};

/* Align the .BTF_ids section to 4 bytes */
asm (
".pushsection " BTF_IDS_SECTION " ,\"a\"; \n"
".balign 4, 0;                            \n"
".popsection;                             \n");

BTF_ID_LIST(test_list_local)
BTF_ID_UNUSED
BTF_ID(typedef, S)
BTF_ID(typedef, T)
BTF_ID(typedef, U)
BTF_ID(struct,  S)
BTF_ID(union,   U)
BTF_ID(func,    func)

extern __u32 test_list_global[];
BTF_ID_LIST_GLOBAL(test_list_global, 1)
BTF_ID_UNUSED
BTF_ID(typedef, S)
BTF_ID(typedef, T)
BTF_ID(typedef, U)
BTF_ID(struct,  S)
BTF_ID(union,   U)
BTF_ID(func,    func)

BTF_SET_START(test_set)
BTF_ID(typedef, S)
BTF_ID(typedef, T)
BTF_ID(typedef, U)
BTF_ID(struct,  S)
BTF_ID(union,   U)
BTF_ID(func,    func)
BTF_SET_END(test_set)

static int
__resolve_symbol(struct btf *btf, int type_id)
{
	const struct btf_type *type;
	const char *str;
	unsigned int i;

	type = btf__type_by_id(btf, type_id);
	if (!ASSERT_OK_PTR(type, "btf__type_by_id"))
		return -1;

	for (i = 0; i < ARRAY_SIZE(test_symbols); i++) {
		if (test_symbols[i].id >= 0)
			continue;

		if (BTF_INFO_KIND(type->info) != test_symbols[i].type)
			continue;

		str = btf__name_by_offset(btf, type->name_off);
		if (!ASSERT_OK_PTR(str, "btf__name_by_offset"))
			return -1;

		if (!strcmp(str, test_symbols[i].name))
			test_symbols[i].id = type_id;
	}

	return 0;
}

static int resolve_symbols(struct btf *btf)
{
	__u32 nr = btf__type_cnt(btf);
	int type_id;

	for (type_id = 1; type_id < nr; type_id++) {
		if (__resolve_symbol(btf, type_id))
			return -1;
	}
	return 0;
}

void test_resolve_btfids(void)
{
	__u32 *test_list, *test_lists[] = { test_list_local, test_list_global };
	unsigned int i, j;
	struct btf *btf;

	btf = btf__parse_raw(BTF_DATA_FILE);
	if (!ASSERT_OK_PTR(btf, "btf_parse"))
		return;

	if (resolve_symbols(btf))
		goto out;

	/* Check BTF_ID_LIST(test_list_local) and
	 * BTF_ID_LIST_GLOBAL(test_list_global) IDs
	 */
	for (j = 0; j < ARRAY_SIZE(test_lists); j++) {
		test_list = test_lists[j];
		for (i = 0; i < ARRAY_SIZE(test_symbols); i++)
			ASSERT_EQ(test_list[i], test_symbols[i].id, test_symbols[i].name);
	}

	/* Check BTF_SET_START(test_set) IDs */
	for (i = 0; i < test_set.cnt; i++) {
		bool found = false;

		for (j = 0; j < ARRAY_SIZE(test_symbols); j++) {
			if (test_symbols[j].id != test_set.ids[i])
				continue;
			found = true;
			break;
		}

		if (!ASSERT_TRUE(found, "id_in_test_symbols"))
			break;

		if (i > 0)
			ASSERT_LE(test_set.ids[i - 1], test_set.ids[i], "sort_check");
	}

out:
	btf__free(btf);
}
