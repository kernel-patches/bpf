// SPDX-License-Identifier: GPL-2.0-only
#include <sys/socket.h>
#include <unistd.h>
#include <bpf/btf.h>
#include <test_progs.h>
#include "bpftool_helpers.h"

#define PIN_PATH	"/sys/fs/bpf/test_bpftool_map_dump_sk_storage"

/* A socket storage map with a single element, keyed on a socket we own. */
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

void test_bpftool_map_dump(void)
{
	int map_fd, sk_fd = -1, value = 42, ret;
	char output[1024];

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

	/* Socket storage can not be iterated, so the dump must fail loudly
	 * rather than print an empty map that holds an element.
	 */
	ret = get_bpftool_command_output("-j map dump pinned " PIN_PATH,
					 output, sizeof(output));
	ASSERT_NEQ(ret, 0, "json dump fails");
	ASSERT_HAS_SUBSTR(output, "\"error\":", "json dump reports an error");

	ret = get_bpftool_command_output("map dump pinned " PIN_PATH " 2>&1",
					 output, sizeof(output));
	ASSERT_NEQ(ret, 0, "plain dump fails");
	ASSERT_HAS_SUBSTR(output, "does not support iteration",
			  "plain dump explains why");

	unlink(PIN_PATH);
out:
	if (sk_fd >= 0)
		close(sk_fd);
	close(map_fd);
}
