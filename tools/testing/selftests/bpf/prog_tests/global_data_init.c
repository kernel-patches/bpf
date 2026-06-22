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

static void test_global_percpu_data_init(void)
{
	struct test_global_percpu_data__percpu init_value = {};
	struct test_global_percpu_data__percpu *init_data;
	int key, prog_fd, err, num_cpus, num_online, i;
	struct test_global_percpu_data *skel = NULL;
	__u64 args[2] = {0x1234ULL, 0x5678ULL};
	size_t init_data_sz;
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

	err = parse_cpu_mask_file("/sys/devices/system/cpu/online", &online, &num_online);
	if (!ASSERT_OK(err, "parse_cpu_mask_file"))
		return;

	skel = test_global_percpu_data__open();
	if (!ASSERT_OK_PTR(skel, "test_global_percpu_data__open"))
		goto out;
	if (!ASSERT_OK_PTR(skel->percpu, "skel->percpu"))
		goto out;

	ASSERT_EQ(skel->percpu->data, -1, "skel->percpu->data");
	ASSERT_FALSE(skel->percpu->run, "skel->percpu->run");
	ASSERT_EQ(skel->percpu->nums[6], 0, "skel->percpu->nums[6]");
	ASSERT_EQ(skel->percpu->struct_data.i, -1, "struct_data.i");
	ASSERT_FALSE(skel->percpu->struct_data.set, "struct_data.set");
	ASSERT_EQ(skel->percpu->struct_data.nums[6], 0, "struct_data.nums[6]");

	map = skel->maps.percpu;
	if (!ASSERT_EQ(bpf_map__type(map), BPF_MAP_TYPE_PERCPU_ARRAY, "bpf_map__type"))
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
	ASSERT_EQ(init_data->struct_data.i, init_value.struct_data.i, "init_value struct_data.i");
	ASSERT_EQ(init_data->struct_data.nums[6], init_value.struct_data.nums[6],
		  "init_value struct_data.nums[6]");
	ASSERT_EQ(init_data_sz, sizeof(init_value), "init_value size");
	ASSERT_EQ((void *) init_data, (void *) skel->percpu, "skel->percpu eq init_data");
	ASSERT_EQ(skel->percpu->data, init_value.data, "skel->percpu->data");
	ASSERT_EQ(skel->percpu->run, init_value.run, "skel->percpu->run");
	ASSERT_EQ(skel->percpu->struct_data.i, init_value.struct_data.i,
		  "skel->percpu->struct_data.i");
	ASSERT_EQ(skel->percpu->struct_data.nums[6], init_value.struct_data.nums[6],
		  "skel->percpu->struct_data.nums[6]");

	err = test_global_percpu_data__load(skel);
	if (!ASSERT_OK(err, "test_global_percpu_data__load"))
		goto out;

	ASSERT_OK_PTR(skel->percpu, "skel->percpu");

	key = 0;
	prog_fd = bpf_program__fd(skel->progs.update_percpu_data);

	/* run on every CPU */
	for (i = 0; i < num_online; i++) {
		struct test_global_percpu_data__percpu data = {};
		__u64 flags;

		if (!online[i])
			continue;

		topts.cpu = i;
		topts.retval = -1;
		err = bpf_prog_test_run_opts(prog_fd, &topts);
		ASSERT_OK(err, "bpf_prog_test_run_opts");
		ASSERT_EQ(topts.retval, 0, "bpf_prog_test_run_opts retval");

		flags = ((__u64) i << 32) | BPF_F_CPU;
		err = bpf_map__lookup_elem(map, &key, sizeof(key), &data, sizeof(data), flags);
		if (!ASSERT_OK(err, "bpf_map__lookup_elem"))
			goto out;

		ASSERT_EQ(data.data, 1, "data.data");
		ASSERT_TRUE(data.run, "data.run");
		ASSERT_EQ(data.nums[6], 0xc0de, "data.nums[6]");
		ASSERT_EQ(data.struct_data.i, 1, "struct_data.i");
		ASSERT_TRUE(data.struct_data.set, "struct_data.set");
		ASSERT_EQ(data.struct_data.nums[6], 0xc0de, "struct_data.nums[6]");
	}

out:
	test_global_percpu_data__destroy(skel);
	free(online);
}

static void test_global_percpu_data_lskel(void)
{
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

	err = parse_cpu_mask_file("/sys/devices/system/cpu/online", &online, &num_online);
	if (!ASSERT_OK(err, "parse_cpu_mask_file"))
		return;

	lskel = test_global_percpu_data_lskel__open_and_load();
	if (!ASSERT_OK_PTR(lskel, "test_global_percpu_data_lskel__open_and_load"))
		goto out;

	key = 0;
	map_fd = lskel->maps.percpu.map_fd;
	prog_fd = lskel->progs.update_percpu_data.prog_fd;

	/* run on every CPU */
	for (i = 0; i < num_online; i++) {
		struct test_global_percpu_data__percpu data = {};
		__u64 flags;

		if (!online[i])
			continue;

		topts.cpu = i;
		topts.retval = -1;
		err = bpf_prog_test_run_opts(prog_fd, &topts);
		ASSERT_OK(err, "bpf_prog_test_run_opts");
		ASSERT_EQ(topts.retval, 0, "bpf_prog_test_run_opts retval");

		flags = ((__u64) i << 32) | BPF_F_CPU;
		err = bpf_map_lookup_elem_flags(map_fd, &key, &data, flags);
		if (!ASSERT_OK(err, "bpf_map_lookup_elem_flags"))
			goto out;

		ASSERT_EQ(data.data, 1, "data.data");
		ASSERT_TRUE(data.run, "data.run");
		ASSERT_EQ(data.nums[6], 0xc0de, "data.nums[6]");
		ASSERT_EQ(data.struct_data.i, 1, "struct_data.i");
		ASSERT_TRUE(data.struct_data.set, "struct_data.set");
		ASSERT_EQ(data.struct_data.nums[6], 0xc0de, "struct_data.nums[6]");
	}

out:
	test_global_percpu_data_lskel__destroy(lskel);
	free(online);
}

static void test_global_percpu_data_rdonly_direct_read(void)
{
	LIBBPF_OPTS(bpf_map_create_opts, map_opts,
		    .map_flags = BPF_F_RDONLY_PROG,
	);
	struct bpf_insn insns[] = {
		BPF_ST_MEM(BPF_W, BPF_REG_10, -8, 0),
		BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
		BPF_LD_MAP_FD(BPF_REG_1, 0),
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
		BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 1),
		BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	int key = 0, map_fd, prog_fd = -1, err;
	__u64 value = 0;

	map_fd = bpf_map_create(BPF_MAP_TYPE_PERCPU_ARRAY, "percpu_ro_map", sizeof(int),
				sizeof(__u64), 1, &map_opts);
	if (!ASSERT_GE(map_fd, 0, "bpf_map_create"))
		return;

	err = bpf_map_update_elem(map_fd, &key, &value, BPF_F_ALL_CPUS);
	if (!ASSERT_OK(err, "bpf_map_update_elem"))
		goto out;

	err = bpf_map_freeze(map_fd);
	if (!ASSERT_OK(err, "bpf_map_freeze"))
		goto out;

	insns[3].imm = map_fd;
	prog_fd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, "percpu_ro_prog", "GPL", insns,
				ARRAY_SIZE(insns), NULL);
	ASSERT_GE(prog_fd, 0, "bpf_prog_load");

out:
	if (prog_fd >= 0)
		close(prog_fd);
	close(map_fd);
}

void test_global_percpu_data(void)
{
	if (!feat_supported(NULL, FEAT_PERCPU_DATA)) {
		test__skip();
		return;
	}

	if (test__start_subtest("init"))
		test_global_percpu_data_init();
	if (test__start_subtest("lskel"))
		test_global_percpu_data_lskel();
	if (test__start_subtest("rdonly_direct_read"))
		test_global_percpu_data_rdonly_direct_read();
}
