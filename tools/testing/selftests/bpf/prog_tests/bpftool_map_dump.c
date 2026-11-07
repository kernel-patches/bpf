// SPDX-License-Identifier: GPL-2.0-only
#include <sys/socket.h>
#include <unistd.h>
#include <bpf/btf.h>
#include <test_progs.h>
#include "bpftool_helpers.h"

#define PIN_PATH	"/sys/fs/bpf/test_bpftool_map_dump_sk_storage"
#define QUEUE_PIN_PATH	"/sys/fs/bpf/test_bpftool_map_dump_queue"
#define ENUM_PIN_PATH	"/sys/fs/bpf/test_bpftool_map_dump_enum"
#define JSON_ERROR	"{\"error\":\"can't dump sk_storage map"

/* An empty socket storage map with an int value. */
static int create_sk_storage_map(void)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts,
		    .map_flags = BPF_F_NO_PREALLOC);
	struct btf *btf;
	int int_id, fd = -1;

	btf = btf__new_empty();
	if (!ASSERT_OK_PTR(btf, "btf__new_empty"))
		return -1;

	int_id = btf__add_int(btf, "int", 4, BTF_INT_SIGNED);
	if (!ASSERT_GT(int_id, 0, "btf__add_int"))
		goto out;
	if (!ASSERT_OK(btf__load_into_kernel(btf), "btf__load_into_kernel"))
		goto out;

	opts.btf_fd = btf__fd(btf);
	opts.btf_key_type_id = int_id;
	opts.btf_value_type_id = int_id;
	fd = bpf_map_create(BPF_MAP_TYPE_SK_STORAGE, "sk_storage", sizeof(int),
			    sizeof(int), 0, &opts);
	ASSERT_OK_FD(fd, "bpf_map_create");
out:
	btf__free(btf);
	return fd;
}

static void test_sk_storage(void)
{
	int map_fd, sk_fd = -1, value = 42, ret;
	char output[1024] = {};

	map_fd = create_sk_storage_map();
	if (map_fd < 0)
		return;

	sk_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (!ASSERT_OK_FD(sk_fd, "socket"))
		goto out;
	if (!ASSERT_OK(bpf_map_update_elem(map_fd, &sk_fd, &value, BPF_NOEXIST),
		       "add socket storage"))
		goto out;
	if (!ASSERT_OK(bpf_obj_pin(map_fd, PIN_PATH), "pin map"))
		goto out;

	/*
	 * Socket storage can't be iterated, so the dump must fail with an
	 * error and nothing else, rather than print an empty map that holds
	 * an element. The buffer is cleared before each run so that a run
	 * that fails to start can't match stale or uninitialised output.
	 */
	ret = get_bpftool_command_output("-j map dump pinned " PIN_PATH,
					 output, sizeof(output));
	ASSERT_NEQ(ret, 0, "json dump fails");
	ASSERT_STRNEQ(output, JSON_ERROR, strlen(JSON_ERROR),
		      "json dump is only the error");

	memset(output, 0, sizeof(output));
	ret = get_bpftool_command_output("map dump pinned " PIN_PATH,
					 output, sizeof(output));
	ASSERT_NEQ(ret, 0, "plain dump fails");
	ASSERT_NULL(strchr(output, '['), "plain dump prints no elements");

	memset(output, 0, sizeof(output));
	get_bpftool_command_output("map dump pinned " PIN_PATH " 2>&1 >/dev/null",
				   output, sizeof(output));
	ASSERT_HAS_SUBSTR(output,
			  "can't dump sk_storage map: Operation not supported",
			  "plain dump explains why on stderr");

out:
	unlink(PIN_PATH);
	if (sk_fd >= 0)
		close(sk_fd);
	close(map_fd);
}

/*
 * A queue map has no BTF, so its plain dump prints an element count
 * rather than JSON. A dump that ignored the error would print "Found 0
 * elements" for a queue that holds one.
 */
static void test_queue(void)
{
	char output[1024] = {};
	int map_fd, value = 42, ret;

	map_fd = bpf_map_create(BPF_MAP_TYPE_QUEUE, "queue", 0, sizeof(int), 1,
				NULL);
	if (!ASSERT_OK_FD(map_fd, "bpf_map_create"))
		return;
	if (!ASSERT_OK(bpf_map_update_elem(map_fd, NULL, &value, BPF_ANY),
		       "push to queue"))
		goto out;
	if (!ASSERT_OK(bpf_obj_pin(map_fd, QUEUE_PIN_PATH), "pin map"))
		goto out;

	ret = get_bpftool_command_output("map dump pinned " QUEUE_PIN_PATH,
					 output, sizeof(output));
	ASSERT_NEQ(ret, 0, "plain dump fails");
	ASSERT_NULL(strstr(output, "Found"), "plain dump prints no count");

	memset(output, 0, sizeof(output));
	get_bpftool_command_output("map dump pinned " QUEUE_PIN_PATH " 2>&1 >/dev/null",
				   output, sizeof(output));
	ASSERT_HAS_SUBSTR(output, "can't dump queue map",
			  "plain dump explains why on stderr");

out:
	unlink(QUEUE_PIN_PATH);
	close(map_fd);
}

enum enum_dump_kind {
	DUMP_ENUM_UNSIGNED,
	DUMP_ENUM_SIGNED,
	DUMP_ENUM64_UNSIGNED,
	DUMP_ENUM64_SIGNED,
};

struct enum_dump_test {
	const char *name;
	enum enum_dump_kind kind;
	__u32 size;
	__u64 value;
	const char *expected;
};

static const struct enum_dump_test enum_dump_tests[] = {
	{ "enum_u8_name", DUMP_ENUM_UNSIGNED, 1, 0xff, "\"MAX\"" },
	{ "enum_u8_unknown", DUMP_ENUM_UNSIGNED, 1, (__u64)-22, "234" },
	{ "enum_u16_name", DUMP_ENUM_UNSIGNED, 2, 0xffff, "\"MAX\"" },
	{ "enum_u16_unknown", DUMP_ENUM_UNSIGNED, 2, (__u64)-22, "65514" },
	{ "enum_u32_high", DUMP_ENUM_UNSIGNED, 4, 0x80000000, "\"HIGH\"" },
	{ "enum_u32_max", DUMP_ENUM_UNSIGNED, 4, 0xffffffff, "\"MAX\"" },
	{ "enum_u32_unknown", DUMP_ENUM_UNSIGNED, 4, (__u64)-22, "4294967274" },
	{ "enum_s8_name", DUMP_ENUM_SIGNED, 1, (__u64)-1, "\"NEG\"" },
	{ "enum_s8_unknown", DUMP_ENUM_SIGNED, 1, (__u64)-22, "-22" },
	{ "enum_s16_name", DUMP_ENUM_SIGNED, 2, (__u64)-1, "\"NEG\"" },
	{ "enum_s32_name", DUMP_ENUM_SIGNED, 4, (__u64)-1, "\"NEG\"" },
	{ "enum_s32_unknown", DUMP_ENUM_SIGNED, 4, (__u64)-22, "-22" },
	{ "enum_wide_name", DUMP_ENUM_UNSIGNED, 8, 0xffffffff, "\"MAX\"" },
	{ "enum_wide_unknown", DUMP_ENUM_UNSIGNED, 8, 0x1ffffffffULL, "8589934591" },
	{ "enum64_unsigned", DUMP_ENUM64_UNSIGNED, 8, (1ULL << 63) | 1,
	  "9223372036854775809" },
	{ "enum64_signed", DUMP_ENUM64_SIGNED, 8, (__u64)-22, "-22" },
};

static int add_enum_dump_values(struct btf *btf, const struct enum_dump_test *test)
{
	__u64 max = test->size == 1 ? 0xff : test->size == 2 ? 0xffff : 0xffffffff;
	int err;

	switch (test->kind) {
	case DUMP_ENUM_UNSIGNED:
		err = btf__add_enum_value(btf, "HIGH", (max >> 1) + 1);
		return err ?: btf__add_enum_value(btf, "MAX", max);
	case DUMP_ENUM_SIGNED:
		return btf__add_enum_value(btf, "NEG", -1);
	case DUMP_ENUM64_UNSIGNED:
		err = btf__add_enum64_value(btf, "HIGH", 1ULL << 63);
		return err ?: btf__add_enum64_value(btf, "LOW", 1);
	case DUMP_ENUM64_SIGNED:
		return btf__add_enum64_value(btf, "NEG", (__u64)-1);
	default:
		return -EINVAL;
	}
}

static int create_enum_dump_map(const struct enum_dump_test *test)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts);
	bool enum64 = test->kind == DUMP_ENUM64_UNSIGNED ||
		      test->kind == DUMP_ENUM64_SIGNED;
	struct btf *btf;
	int key_id, value_id, fd = -1;

	btf = btf__new_empty();
	if (!ASSERT_OK_PTR(btf, "btf__new_empty"))
		return -1;

	key_id = btf__add_int(btf, "int", 4, BTF_INT_SIGNED);
	if (!ASSERT_GT(key_id, 0, "btf__add_int"))
		goto out;
	if (enum64)
		value_id = btf__add_enum64(btf, "enum_value", test->size,
					   test->kind == DUMP_ENUM64_SIGNED);
	else
		value_id = btf__add_enum(btf, "enum_value", test->size);
	if (!ASSERT_GT(value_id, 0, "add enum"))
		goto out;
	if (!ASSERT_OK(add_enum_dump_values(btf, test), "add enum values"))
		goto out;
	if (!ASSERT_OK(btf__load_into_kernel(btf), "btf__load_into_kernel"))
		goto out;

	opts.btf_fd = btf__fd(btf);
	opts.btf_key_type_id = key_id;
	opts.btf_value_type_id = value_id;
	fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "enum_dump", sizeof(__u32),
			    test->size, 1, &opts);
	ASSERT_OK_FD(fd, "bpf_map_create");
out:
	btf__free(btf);
	return fd;
}

static void test_enum_dump(const struct enum_dump_test *test)
{
	union {
		__u8 val8;
		__u16 val16;
		__u32 val32;
		__u64 val64;
	} value;
	char output[1024] = {}, expected[128];
	__u32 key = 0;
	int map_fd, ret;

	/* Store the value at its native width, including on big-endian hosts. */
	switch (test->size) {
	case 1:
		value.val8 = (__u8)test->value;
		break;
	case 2:
		value.val16 = (__u16)test->value;
		break;
	case 4:
		value.val32 = (__u32)test->value;
		break;
	case 8:
		value.val64 = test->value;
		break;
	default:
		PRINT_FAIL("unexpected enum size %u (expected 1, 2, 4 or 8)\n", test->size);
		return;
	}

	map_fd = create_enum_dump_map(test);
	if (map_fd < 0)
		return;
	if (!ASSERT_OK(bpf_map_update_elem(map_fd, &key, &value, BPF_ANY),
		       "update enum value"))
		goto out;
	if (!ASSERT_OK(bpf_obj_pin(map_fd, ENUM_PIN_PATH), "pin enum map"))
		goto out;

	ret = get_bpftool_command_output("-j map dump pinned " ENUM_PIN_PATH,
					 output, sizeof(output));
	if (!ASSERT_OK(ret, "json enum dump"))
		goto out;
	snprintf(expected, sizeof(expected), "\"formatted\":{\"key\":0,\"value\":%s}",
		 test->expected);
	ASSERT_HAS_SUBSTR(output, expected, "json enum value");

	memset(output, 0, sizeof(output));
	ret = get_bpftool_command_output("map dump pinned " ENUM_PIN_PATH,
					 output, sizeof(output));
	if (!ASSERT_OK(ret, "plain enum dump"))
		goto out;
	snprintf(expected, sizeof(expected), "\"value\": %s\n", test->expected);
	ASSERT_HAS_SUBSTR(output, expected, "plain enum value");
out:
	unlink(ENUM_PIN_PATH);
	close(map_fd);
}

void test_bpftool_map_dump(void)
{
	size_t i;

	if (test__start_subtest("sk_storage"))
		test_sk_storage();
	if (test__start_subtest("queue"))
		test_queue();

	for (i = 0; i < ARRAY_SIZE(enum_dump_tests); i++) {
		if (test__start_subtest(enum_dump_tests[i].name))
			test_enum_dump(&enum_dump_tests[i]);
	}
}
