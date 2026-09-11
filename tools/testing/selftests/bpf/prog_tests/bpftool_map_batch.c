// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <bpftool_helpers.h>
#include <bpf/btf.h>
#include <ctype.h>

#define MAX_ENTRIES 1025
#define RECORD_SIZE 256
#define OUTPUT_SIZE (MAX_ENTRIES * RECORD_SIZE + 1024)

struct dump_case {
	const char *name;
	unsigned int count;
	unsigned int key_size;
	unsigned int value_size;
	bool btf;
};

static void hex_bytes(char *out, const void *data, unsigned int size, bool json)
{
	const unsigned char *bytes = data;
	unsigned int i;

	if (json)
		*out++ = '[';
	for (i = 0; i < size; i++) {
		if (json && i)
			*out++ = ',';
		out += sprintf(out, json ? "\"0x%02x\"" : "%02x", bytes[i]);
	}
	if (json)
		*out++ = ']';
	*out = '\0';
}

static void expected_record(char *record, const struct dump_case *test,
			    unsigned int index, bool json)
{
	__u32 key = index, value = index * 37 + 11;
	unsigned char short_key = index;
	char key_hex[64], value_hex[64], formatted[96];

	hex_bytes(key_hex, test->key_size == 1 ? (void *)&short_key : &key,
		  test->key_size, json);
	hex_bytes(value_hex, &value, test->value_size, json);
	snprintf(formatted, sizeof(formatted), "{\"key\":%u,\"value\":%u}",
		 key, value);
	if (json && test->btf)
		snprintf(record, RECORD_SIZE,
			 "{\"key\":%s,\"value\":%s,\"formatted\":%s}",
			 key_hex, value_hex, formatted);
	else if (json)
		snprintf(record, RECORD_SIZE, "{\"key\":%s,\"value\":%s}",
			 key_hex, value_hex);
	else if (test->btf)
		snprintf(record, RECORD_SIZE, "%s", formatted);
	else
		snprintf(record, RECORD_SIZE, "key:%svalue:%s", key_hex, value_hex);
}

static void check_dump(const struct dump_case *test, __u32 id, bool json, bool pretty)
{
	bool array = json || test->btf;
	char command[MAX_BPFTOOL_CMD_LEN], expected[RECORD_SIZE], footer[64];
	bool seen[MAX_ENTRIES] = {};
	char *output, *src, *dst, *cursor;
	unsigned int i, n;
	int err;

	output = calloc(1, OUTPUT_SIZE);
	if (!ASSERT_OK_PTR(output, "alloc_output"))
		return;
	snprintf(command, sizeof(command), "%smap dump id %u",
		 pretty ? "-p " : json ? "-j " : "", id);
	err = get_bpftool_command_output(command, output, OUTPUT_SIZE);
	if (!ASSERT_OK(err, "map_dump"))
		goto out;
	/*
	 * Ignore presentation whitespace, but compare complete records and all
	 * punctuation. Expected contents come only from the input data, never
	 * from another map walk or bpftool invocation.
	 */
	for (src = output, dst = output; *src; src++)
		if (!isspace((unsigned char)*src))
			*dst++ = *src;
	*dst = '\0';
	cursor = output;
	if (array) {
		if (!ASSERT_EQ(*cursor, '[', "array_start"))
			goto out;
		cursor++;
	}
	for (n = 0; n < test->count; n++) {
		if (array && n) {
			if (!ASSERT_EQ(*cursor, ',', "record_separator"))
				goto out;
			cursor++;
		}
		for (i = 0; i < test->count; i++) {
			if (seen[i])
				continue;
			expected_record(expected, test, i, json);
			if (!strncmp(cursor, expected, strlen(expected)))
				break;
		}
		if (!ASSERT_LT(i, test->count, "unique_expected_record"))
			goto out;
		seen[i] = true;
		cursor += strlen(expected);
	}
	if (array) {
		ASSERT_STREQ(cursor, "]", "array_end_and_count");
	} else {
		snprintf(footer, sizeof(footer), "Found%uelement%s", test->count,
			 test->count == 1 ? "" : "s");
		ASSERT_STREQ(cursor, footer, "plain_count");
	}
out:
	free(output);
}

static void run_dump_case(const struct dump_case *test)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts);
	struct bpf_map_info info = {};
	__u32 info_len = sizeof(info);
	struct btf *btf = NULL;
	unsigned int i;
	int fd = -1;

	if (test->btf) {
		btf = btf__new_empty();
		if (!ASSERT_OK_PTR(btf, "btf_new"))
			return;
		if (!ASSERT_EQ(btf__add_int(btf, "unsigned int", 4, 0), 1,
			       "btf_int") ||
		    !ASSERT_OK(btf__load_into_kernel(btf), "btf_load"))
			goto out;
		opts.btf_fd = btf__fd(btf);
		opts.btf_key_type_id = 1;
		opts.btf_value_type_id = 1;
	}
	fd = bpf_map_create(BPF_MAP_TYPE_HASH, "dump_batch", test->key_size,
			    test->value_size, test->count ?: 1, &opts);
	if (!ASSERT_OK_FD(fd, "map_create"))
		goto out;
	for (i = 0; i < test->count; i++) {
		__u32 key = i, value = i * 37 + 11;
		unsigned char short_key = i;
		void *key_ptr = test->key_size == 1 ? (void *)&short_key : &key;

		if (!ASSERT_OK(bpf_map_update_elem(fd, key_ptr, &value, BPF_ANY),
			       "map_update"))
			goto out;
	}
	if (!ASSERT_OK(bpf_map_get_info_by_fd(fd, &info, &info_len), "map_info"))
		goto out;
	check_dump(test, info.id, false, false);
	check_dump(test, info.id, true, false);
	check_dump(test, info.id, true, true);
out:
	if (fd >= 0)
		close(fd);
	btf__free(btf);
}

void test_bpftool_map_batch(void)
{
	static const struct dump_case cases[] = {
		{ "empty", 0, 4, 4 },
		{ "single", 1, 4, 4 },
		{ "below_batch", 255, 4, 4 },
		{ "exact_batch", 256, 4, 4 },
		{ "above_batch", 257, 4, 4 },
		{ "multiple_batches", 1025, 4, 4 },
		{ "one_byte_key", 256, 1, 4 },
		{ "odd_value_size", 257, 4, 3 },
		{ "btf_empty", 0, 4, 4, true },
		{ "btf_single", 1, 4, 4, true },
		{ "btf_multiple_batches", 1025, 4, 4, true },
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(cases); i++)
		if (test__start_subtest(cases[i].name))
			run_dump_case(&cases[i]);
}
