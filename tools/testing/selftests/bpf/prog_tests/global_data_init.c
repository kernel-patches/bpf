// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "bpf/libbpf_internal.h"
#include "test_global_percpu_data.skel.h"
#include "test_global_percpu_data.lskel.h"

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
	struct test_global_percpu_data__data__percpu init_value, *init_data, *data, *percpu_data;
	int key, prog_fd, err, num_cpus, num_online, i;
	struct test_global_percpu_data *skel = NULL;
	__u64 args[2] = {0x1234ULL, 0x5678ULL};
	size_t elem_sz, init_data_sz;
	struct bpf_map *map;
	bool *online;
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		    .ctx_in = args,
		    .ctx_size_in = sizeof(args),
		    .flags = BPF_F_TEST_RUN_ON_CPU,
	);

	num_cpus = libbpf_num_possible_cpus();
	if (!ASSERT_GT(num_cpus, 0, "libbpf_num_possible_cpus"))
		return;

	err = parse_cpu_mask_file("/sys/devices/system/cpu/online",
				  &online, &num_online);
	if (!ASSERT_OK(err, "parse_cpu_mask_file"))
		return;

	elem_sz = sizeof(*percpu_data);
	percpu_data = calloc(num_cpus, elem_sz);
	if (!ASSERT_OK_PTR(percpu_data, "calloc percpu_data"))
		goto out;

	skel = test_global_percpu_data__open();
	if (!ASSERT_OK_PTR(skel, "test_global_percpu_data__open"))
		goto out;
	if (!ASSERT_OK_PTR(skel->data__percpu, "skel->data__percpu"))
		goto out;

	ASSERT_EQ(skel->data__percpu->data, -1, "skel->data__percpu->data");
	ASSERT_FALSE(skel->data__percpu->run, "skel->data__percpu->run");
	ASSERT_EQ(skel->data__percpu->nums[6], 0, "skel->data__percpu->nums[6]");
	ASSERT_EQ(skel->data__percpu->struct_data.i, -1, "struct_data.i");
	ASSERT_FALSE(skel->data__percpu->struct_data.set, "struct_data.set");
	ASSERT_EQ(skel->data__percpu->struct_data.nums[6], 0, "struct_data.nums[6]");

	map = skel->maps.data__percpu;
	if (!ASSERT_EQ(bpf_map__type(map), BPF_MAP_TYPE_PERCPU_ARRAY, "bpf_map__type"))
		goto out;
	if (!ASSERT_TRUE(bpf_map__is_internal_percpu(map), "bpf_map__is_internal_percpu"))
		goto out;

	init_value.data = 2;
	init_value.nums[6] = -1;
	init_value.struct_data.i = 2;
	init_value.struct_data.nums[6] = -1;
	err = bpf_map__set_initial_value(map, &init_value, sizeof(init_value));
	if (!ASSERT_OK(err, "bpf_map__set_initial_value"))
		goto out;

	init_data = bpf_map__initial_value(map, &init_data_sz);
	if (!ASSERT_OK_PTR(init_data, "bpf_map__initial_value"))
		goto out;

	ASSERT_EQ(init_data->data, init_value.data, "init_value data");
	ASSERT_EQ(init_data->run, init_value.run, "init_value run");
	ASSERT_EQ(init_data->struct_data.i, init_value.struct_data.i,
		  "init_value struct_data.i");
	ASSERT_EQ(init_data->struct_data.nums[6],
		  init_value.struct_data.nums[6],
		  "init_value struct_data.nums[6]");
	ASSERT_EQ(init_data_sz, sizeof(init_value), "init_value size");
	ASSERT_EQ((void *) init_data, (void *) skel->data__percpu,
		  "skel->data__percpu eq init_data");
	ASSERT_EQ(skel->data__percpu->data, init_value.data,
		  "skel->data__percpu->data");
	ASSERT_EQ(skel->data__percpu->run, init_value.run,
		  "skel->data__percpu->run");
	ASSERT_EQ(skel->data__percpu->struct_data.i, init_value.struct_data.i,
		  "skel->data__percpu->struct_data.i");
	ASSERT_EQ(skel->data__percpu->struct_data.nums[6],
		  init_value.struct_data.nums[6],
		  "skel->data__percpu->struct_data.nums[6]");

	err = test_global_percpu_data__load(skel);
	if (err == -EOPNOTSUPP) {
		test__skip();
		goto out;
	}
	if (!ASSERT_OK(err, "test_global_percpu_data__load"))
		goto out;

	ASSERT_NULL(skel->data__percpu, "skel->data__percpu");

	err = test_global_percpu_data__attach(skel);
	if (!ASSERT_OK(err, "test_global_percpu_data__attach"))
		goto out;

	prog_fd = bpf_program__fd(skel->progs.update_percpu_data);

	/* run on every CPU */
	for (i = 0; i < num_online; i++) {
		if (!online[i])
			continue;

		topts.cpu = i;
		topts.retval = 0;
		err = bpf_prog_test_run_opts(prog_fd, &topts);
		ASSERT_OK(err, "bpf_prog_test_run_opts");
		ASSERT_EQ(topts.retval, 0, "bpf_prog_test_run_opts retval");
	}

	key = 0;
	err = bpf_map__lookup_elem(map, &key, sizeof(key), percpu_data,
				   elem_sz * num_cpus, 0);
	if (!ASSERT_OK(err, "bpf_map__lookup_elem"))
		goto out;

	for (i = 0; i < num_online; i++) {
		if (!online[i])
			continue;

		data = percpu_data + i;
		ASSERT_EQ(data->data, 1, "percpu_data->data");
		ASSERT_TRUE(data->run, "percpu_data->run");
		ASSERT_EQ(data->nums[6], 0xc0de, "percpu_data->nums[6]");
		ASSERT_EQ(data->struct_data.i, 1, "struct_data.i");
		ASSERT_TRUE(data->struct_data.set, "struct_data.set");
		ASSERT_EQ(data->struct_data.nums[6], 0xc0de, "struct_data.nums[6]");
	}

out:
	test_global_percpu_data__destroy(skel);
	if (percpu_data)
		free(percpu_data);
	free(online);
}

void test_global_percpu_data_lskel(void)
{
	struct test_global_percpu_data__data__percpu *data, *percpu_data;
	int key, prog_fd, map_fd, err, num_cpus, num_online, i;
	struct test_global_percpu_data_lskel *lskel = NULL;
	__u64 args[2] = {0x1234ULL, 0x5678ULL};
	bool *online;
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		    .ctx_in = args,
		    .ctx_size_in = sizeof(args),
		    .flags = BPF_F_TEST_RUN_ON_CPU,
	);

	num_cpus = libbpf_num_possible_cpus();
	if (!ASSERT_GT(num_cpus, 0, "libbpf_num_possible_cpus"))
		return;

	err = parse_cpu_mask_file("/sys/devices/system/cpu/online",
				  &online, &num_online);
	if (!ASSERT_OK(err, "parse_cpu_mask_file"))
		return;

	percpu_data = calloc(num_cpus, sizeof(*percpu_data));
	if (!ASSERT_OK_PTR(percpu_data, "calloc percpu_data"))
		goto out;

	lskel = test_global_percpu_data_lskel__open();
	if (!ASSERT_OK_PTR(lskel, "test_global_percpu_data_lskel__open"))
		goto out;

	err = test_global_percpu_data_lskel__load(lskel);
	if (err == -EOPNOTSUPP) {
		test__skip();
		goto out;
	}
	if (!ASSERT_OK(err, "test_global_percpu_data_lskel__load"))
		goto out;

	err = test_global_percpu_data_lskel__attach(lskel);
	if (!ASSERT_OK(err, "test_global_percpu_data_lskel__attach"))
		goto out;

	prog_fd = lskel->progs.update_percpu_data.prog_fd;

	/* run on every CPU */
	for (i = 0; i < num_online; i++) {
		if (!online[i])
			continue;

		topts.cpu = i;
		topts.retval = 0;
		err = bpf_prog_test_run_opts(prog_fd, &topts);
		ASSERT_OK(err, "bpf_prog_test_run_opts");
		ASSERT_EQ(topts.retval, 0, "bpf_prog_test_run_opts retval");
	}

	key = 0;
	map_fd = lskel->maps.data__percpu.map_fd;
	err = bpf_map_lookup_elem(map_fd, &key, percpu_data);
	if (!ASSERT_OK(err, "bpf_map_lookup_elem"))
		goto out;

	for (i = 0; i < num_online; i++) {
		if (!online[i])
			continue;

		data = percpu_data + i;
		ASSERT_EQ(data->data, 1, "percpu_data->data");
		ASSERT_TRUE(data->run, "percpu_data->run");
		ASSERT_EQ(data->nums[6], 0xc0de, "percpu_data->nums[6]");
		ASSERT_EQ(data->struct_data.i, 1, "struct_data.i");
		ASSERT_TRUE(data->struct_data.set, "struct_data.set");
		ASSERT_EQ(data->struct_data.nums[6], 0xc0de, "struct_data.nums[6]");
	}

out:
	test_global_percpu_data_lskel__destroy(lskel);
	if (percpu_data)
		free(percpu_data);
	free(online);
}
