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

struct enums {
	__u8 u8_name;
	__s8 s8_name;
	__u32 u32_num;
	__u64 u64_num;
};

/* An array map. Its value is struct enums with an enum behind every member. */
static int create_enum_map(void)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts);
	struct btf *btf;
	int fd = -1;

	btf = btf__new_empty();
	if (!ASSERT_OK_PTR(btf, "btf__new_empty"))
		return -1;

	btf__add_int(btf, "int", 4, BTF_INT_SIGNED);	/* [1] */
	btf__add_enum(btf, "u8", 1);			/* [2] */
	btf__add_enum_value(btf, "U8_MAX", 0xff);
	btf__add_enum(btf, "s8", 1);			/* [3] */
	btf__add_enum_value(btf, "S8_NEG", -1);
	btf__add_enum(btf, "u32", 4);			/* [4] */
	btf__add_enum_value(btf, "U32_ONE", 1);
	btf__add_enum64(btf, "u64", 8, false);		/* [5] */
	btf__add_enum64_value(btf, "U64_ONE", 1);
	btf__add_struct(btf, "enums", sizeof(struct enums)); /* [6] */
	btf__add_field(btf, "u8_name", 2, 0, 0);
	btf__add_field(btf, "s8_name", 3, 8, 0);
	btf__add_field(btf, "u32_num", 4, 32, 0);
	btf__add_field(btf, "u64_num", 5, 64, 0);
	if (!ASSERT_OK(btf__load_into_kernel(btf), "btf__load_into_kernel"))
		goto out;

	opts.btf_fd = btf__fd(btf);
	opts.btf_key_type_id = 1;
	opts.btf_value_type_id = 6;
	fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "enums", sizeof(int),
			    sizeof(struct enums), 1, &opts);
	ASSERT_OK_FD(fd, "bpf_map_create");
out:
	btf__free(btf);
	return fd;
}

static void test_enum(void)
{
	struct enums value = { 0xff, -1, (__u32)-22, (1ULL << 63) | 1 };
	char output[1024] = {};
	int map_fd, key = 0, ret;

	map_fd = create_enum_map();
	if (map_fd < 0)
		return;
	if (!ASSERT_OK(bpf_map_update_elem(map_fd, &key, &value, BPF_ANY),
		       "update map"))
		goto out;
	if (!ASSERT_OK(bpf_obj_pin(map_fd, ENUM_PIN_PATH), "pin map"))
		goto out;

	ret = get_bpftool_command_output("-j map dump pinned " ENUM_PIN_PATH,
					 output, sizeof(output));
	ASSERT_OK(ret, "json dump");
	ASSERT_HAS_SUBSTR(output,
			  "{\"u8_name\":\"U8_MAX\",\"s8_name\":\"S8_NEG\","
			  "\"u32_num\":4294967274,\"u64_num\":9223372036854775809}",
			  "enum values");
out:
	unlink(ENUM_PIN_PATH);
	close(map_fd);
}

void test_bpftool_map_dump(void)
{
	if (test__start_subtest("sk_storage"))
		test_sk_storage();
	if (test__start_subtest("queue"))
		test_queue();
	if (test__start_subtest("enum"))
		test_enum();
}
