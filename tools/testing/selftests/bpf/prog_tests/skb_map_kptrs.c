// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>

#define SKB_KPTR_MAP_PATH "/sys/fs/bpf/skb_kptr_map"

static void skb_map_kptrs(void)
{
	int err, prog_fd, store_fd, get_fd, map_fd;
	struct bpf_program *prog;
	struct bpf_object *obj;
	char buff[128] = {};
	struct bpf_map *map;
	int i;
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = buff,
		.data_size_in = sizeof(buff),
		.repeat = 1,
	);

	err = bpf_prog_test_load("skb_map_kptrs.bpf.o", BPF_PROG_TYPE_SCHED_CLS, &obj,
				 &prog_fd);
	if (CHECK_FAIL(err))
		return;

	map = bpf_object__find_map_by_name(obj, "skb_map");
	if (CHECK_FAIL(!map))
		goto map_err;

	map_fd = bpf_map__fd(map);
	if (map_fd < 0)
		goto map_err;

	err = bpf_obj_pin(map_fd, SKB_KPTR_MAP_PATH);
	if (err < 0)
		goto map_err;

	prog = bpf_object__find_program_by_name(obj, "tc_skb_map_store");
	if (CHECK_FAIL(!prog))
		goto out;

	store_fd = bpf_program__fd(prog);
	if (CHECK_FAIL(store_fd < 0))
		goto out;

	// store skbs
	for (i = 0; i < bpf_map__max_entries(map); i++) {
		err = bpf_prog_test_run_opts(store_fd, &topts);
		ASSERT_OK(err, "skb kptr store");
	}

	prog = bpf_object__find_program_by_name(obj, "tc_skb_map_get");
	if (CHECK_FAIL(!prog))
		goto out;

	get_fd = bpf_program__fd(prog);
	if (CHECK_FAIL(get_fd < 0))
		goto out;

	// get skbs
	for (i = 0; i < bpf_map__max_entries(map); i++) {
		err = bpf_prog_test_run_opts(get_fd, &topts);
		ASSERT_OK(err, "skb kptr get");
	}

out:
	unlink(SKB_KPTR_MAP_PATH);
map_err:
	bpf_object__close(obj);
}

void test_skb_map_kptrs(void)
{
	skb_map_kptrs();
}

