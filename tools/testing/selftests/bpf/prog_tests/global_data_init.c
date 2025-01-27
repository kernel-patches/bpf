// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "test_global_percpu_data.skel.h"

void test_global_data_init(void)
{
	const char *file = "./test_global_data.bpf.o";
	int err = -ENOMEM, map_fd, zero = 0;
	__u8 *buff = NULL, *newval = NULL;
	struct bpf_object *obj;
	struct bpf_map *map;
	__u32 duration = 0;
	size_t sz;

	obj = bpf_object__open_file(file, NULL);
	err = libbpf_get_error(obj);
	if (CHECK_FAIL(err))
		return;

	map = bpf_object__find_map_by_name(obj, ".rodata");
	if (CHECK_FAIL(!map || !bpf_map__is_internal(map)))
		goto out;

	sz = bpf_map__value_size(map);
	newval = malloc(sz);
	if (CHECK_FAIL(!newval))
		goto out;

	memset(newval, 0, sz);
	/* wrong size, should fail */
	err = bpf_map__set_initial_value(map, newval, sz - 1);
	if (CHECK(!err, "reject set initial value wrong size", "err %d\n", err))
		goto out;

	err = bpf_map__set_initial_value(map, newval, sz);
	if (CHECK(err, "set initial value", "err %d\n", err))
		goto out;

	err = bpf_object__load(obj);
	if (CHECK_FAIL(err))
		goto out;

	map_fd = bpf_map__fd(map);
	if (CHECK_FAIL(map_fd < 0))
		goto out;

	buff = malloc(sz);
	if (buff)
		err = bpf_map_lookup_elem(map_fd, &zero, buff);
	if (CHECK(!buff || err || memcmp(buff, newval, sz),
		  "compare .rodata map data override",
		  "err %d errno %d\n", err, errno))
		goto out;

	memset(newval, 1, sz);
	/* object loaded - should fail */
	err = bpf_map__set_initial_value(map, newval, sz);
	CHECK(!err, "reject set initial value after load", "err %d\n", err);
out:
	free(buff);
	free(newval);
	bpf_object__close(obj);
}

void test_global_percpu_data_init(void)
{
	struct test_global_percpu_data *skel = NULL;
	u64 *percpu_data = NULL;
	struct bpf_map *map;
	size_t init_data_sz;
	char buff[128] = {};
	int init_value = 2;
	int key, value_sz;
	int prog_fd, err;
	int *init_data;
	int num_cpus;

	LIBBPF_OPTS(bpf_test_run_opts, topts,
		    .data_in = buff,
		    .data_size_in = sizeof(buff),
		    .repeat = 1,
	);

	num_cpus = libbpf_num_possible_cpus();
	if (!ASSERT_GT(num_cpus, 0, "libbpf_num_possible_cpus"))
		return;

	percpu_data = calloc(num_cpus, sizeof(*percpu_data));
	if (!ASSERT_FALSE(percpu_data == NULL, "calloc percpu_data"))
		return;

	value_sz = sizeof(*percpu_data) * num_cpus;
	memset(percpu_data, 0, value_sz);

	skel = test_global_percpu_data__open();
	if (!ASSERT_OK_PTR(skel, "test_global_percpu_data__open"))
		goto out;

	ASSERT_EQ(skel->percpu->percpu_data, -1, "skel->percpu->percpu_data");

	map = skel->maps.percpu;
	err = bpf_map__set_initial_value(map, &init_value,
					 sizeof(init_value));
	if (!ASSERT_OK(err, "bpf_map__set_initial_value"))
		goto out;

	init_data = bpf_map__initial_value(map, &init_data_sz);
	if (!ASSERT_OK_PTR(init_data, "bpf_map__initial_value"))
		goto out;

	ASSERT_EQ(*init_data, init_value, "initial_value");
	ASSERT_EQ(init_data_sz, sizeof(init_value), "initial_value size");

	if (!ASSERT_EQ((void *) init_data, (void *) skel->percpu, "skel->percpu"))
		goto out;
	ASSERT_EQ(skel->percpu->percpu_data, init_value, "skel->percpu->percpu_data");

	err = test_global_percpu_data__load(skel);
	if (err == -EOPNOTSUPP)
		goto out;
	if (!ASSERT_OK(err, "test_global_percpu_data__load"))
		goto out;

	ASSERT_EQ(bpf_map__type(map), BPF_MAP_TYPE_PERCPU_ARRAY,
		  "bpf_map__type");

	prog_fd = bpf_program__fd(skel->progs.update_percpu_data);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "update_percpu_data");
	ASSERT_EQ(topts.retval, 0, "update_percpu_data retval");

	key = 0;
	err = bpf_map__lookup_elem(map, &key, sizeof(key), percpu_data,
				   value_sz, 0);
	if (!ASSERT_OK(err, "bpf_map__lookup_elem"))
		goto out;

	if (!ASSERT_LT(skel->bss->curr_cpu, num_cpus, "curr_cpu"))
		goto out;
	ASSERT_EQ((int) percpu_data[skel->bss->curr_cpu], 1, "percpu_data");
	if (num_cpus > 1)
		ASSERT_EQ((int) percpu_data[(skel->bss->curr_cpu+1)%num_cpus],
			  init_value, "init_value");

out:
	test_global_percpu_data__destroy(skel);
	if (percpu_data)
		free(percpu_data);
}
