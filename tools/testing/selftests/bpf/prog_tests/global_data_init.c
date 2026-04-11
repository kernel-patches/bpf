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
	struct test_global_percpu_data__percpu *init_data, *data = NULL;
	struct test_global_percpu_data__percpu init_value = {};
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

	err = parse_cpu_mask_file("/sys/devices/system/cpu/online", &online, &num_online);
	if (!ASSERT_OK(err, "parse_cpu_mask_file"))
		return;

	elem_sz = roundup(sizeof(*data), 8);
	data = calloc(1, elem_sz);
	if (!ASSERT_OK_PTR(data, "calloc data"))
		goto out;

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
		__u64 flags;

		if (!online[i])
			continue;

		topts.cpu = i;
		topts.retval = 0;
		err = bpf_prog_test_run_opts(prog_fd, &topts);
		ASSERT_OK(err, "bpf_prog_test_run_opts");
		ASSERT_EQ(topts.retval, 0, "bpf_prog_test_run_opts retval");

		flags = ((__u64) i << 32) | BPF_F_CPU;
		err = bpf_map__lookup_elem(map, &key, sizeof(key), data, elem_sz, flags);
		if (!ASSERT_OK(err, "bpf_map__lookup_elem"))
			goto out;

		ASSERT_EQ(data->data, 1, "data->data");
		ASSERT_TRUE(data->run, "data->run");
		ASSERT_EQ(data->nums[6], 0xc0de, "data->nums[6]");
		ASSERT_EQ(data->struct_data.i, 1, "struct_data.i");
		ASSERT_TRUE(data->struct_data.set, "struct_data.set");
		ASSERT_EQ(data->struct_data.nums[6], 0xc0de, "struct_data.nums[6]");
	}

out:
	test_global_percpu_data__destroy(skel);
	free(data);
	free(online);
}

static void test_global_percpu_data_lskel(void)
{
	int key, prog_fd, map_fd, err, num_cpus, num_online, i;
	struct test_global_percpu_data__percpu *data = NULL;
	struct test_global_percpu_data_lskel *lskel = NULL;
	__u64 args[2] = {0x1234ULL, 0x5678ULL};
	size_t elem_sz;
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

	elem_sz = roundup(sizeof(*data), 8);
	data = calloc(1, elem_sz);
	if (!ASSERT_OK_PTR(data, "calloc data"))
		goto out;

	lskel = test_global_percpu_data_lskel__open_and_load();
	if (!ASSERT_OK_PTR(lskel, "test_global_percpu_data_lskel__open_and_load"))
		goto out;

	key = 0;
	map_fd = lskel->maps.percpu.map_fd;
	prog_fd = lskel->progs.update_percpu_data.prog_fd;

	/* run on every CPU */
	for (i = 0; i < num_online; i++) {
		__u64 flags;

		if (!online[i])
			continue;

		topts.cpu = i;
		topts.retval = 0;
		err = bpf_prog_test_run_opts(prog_fd, &topts);
		ASSERT_OK(err, "bpf_prog_test_run_opts");
		ASSERT_EQ(topts.retval, 0, "bpf_prog_test_run_opts retval");

		flags = ((__u64) i << 32) | BPF_F_CPU;
		err = bpf_map_lookup_elem_flags(map_fd, &key, data, flags);
		if (!ASSERT_OK(err, "bpf_map_lookup_elem_flags"))
			goto out;

		ASSERT_EQ(data->data, 1, "data->data");
		ASSERT_TRUE(data->run, "data->run");
		ASSERT_EQ(data->nums[6], 0xc0de, "data->nums[6]");
		ASSERT_EQ(data->struct_data.i, 1, "struct_data.i");
		ASSERT_TRUE(data->struct_data.set, "struct_data.set");
		ASSERT_EQ(data->struct_data.nums[6], 0xc0de, "struct_data.nums[6]");
	}

out:
	test_global_percpu_data_lskel__destroy(lskel);
	free(data);
	free(online);
}

static void test_global_percpu_data_verifier_log(void)
{
	RUN_TESTS(test_global_percpu_data);
}

static int find_ld_imm64(const struct bpf_insn *insns, size_t insn_cnt, struct bpf_insn *ld_imm64)
{
	size_t i;

	for (i = 0; i < insn_cnt; i++) {
		if (insns[i].code == (BPF_LD | BPF_IMM | BPF_DW)) {
			ld_imm64[0] = insns[i];
			ld_imm64[1] = insns[i + 1];
			return i;
		}
	}

	return -ENOENT;
}

/*
 * Special (internal-only) form of mov, used to resolve per-CPU addrs:
 * dst_reg = src_reg + <percpu_base_off>
 * BPF_ADDR_PERCPU is used as a special insn->off value.
 */
#define BPF_ADDR_PERCPU	(-1)

#define BPF_MOV64_PERCPU_REG(DST, SRC)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_MOV | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = BPF_ADDR_PERCPU,			\
		.imm   = 0 })

static __u64 ld_imm64_to_u64(const struct bpf_insn *insn)
{
	return ((__u64) insn[1].imm << 32) | (__u64) insn[0].imm;
}

static void test_global_percpu_data_xlated(void)
{
	struct bpf_insn ld_imm64_raw[2], ld_imm64_xlated[2], mov64_percpu_reg, *insns = NULL;
	size_t insn_sz = sizeof(struct bpf_insn);
	struct test_global_percpu_data *skel;
	struct bpf_program *prog;
	int idx, err;
	__u32 cnt;

	skel = test_global_percpu_data__open();
	if (!ASSERT_OK_PTR(skel, "test_global_percpu_data__open"))
		return;

	prog = skel->progs.verifier_percpu_read;
	idx = find_ld_imm64(bpf_program__insns(prog), bpf_program__insn_cnt(prog), ld_imm64_raw);
	if (!ASSERT_GE(idx, 0, "find_ld_imm64 raw"))
		goto out;

	err = test_global_percpu_data__load(skel);
	if (!ASSERT_OK(err, "test_global_percpu_data__load"))
		goto out;

	err = get_xlated_program(bpf_program__fd(prog), &insns, &cnt);
	if (!ASSERT_OK(err, "get_xlated_program"))
		goto out;
	if (!ASSERT_GT(cnt, idx + 2, "xlated insn count"))
		goto out;

	idx = find_ld_imm64(insns, cnt, ld_imm64_xlated);
	if (!ASSERT_GE(idx, 0, "find_ld_imm64 xlated"))
		goto out;

	ASSERT_EQ(ld_imm64_xlated[0].code, ld_imm64_raw[0].code, "ld_imm64 opcode");
	ASSERT_TRUE(ld_imm64_xlated[0].dst_reg == ld_imm64_raw[0].dst_reg, "ld_imm64 dst_reg");
	/*
	 * The xlated instruction has the map ID in imm and the offset
	 * in the next instruction's imm. The raw instruction just has
	 * the offset in its imm.
	 */
	ASSERT_EQ(ld_imm64_xlated[1].imm, ld_imm64_to_u64(ld_imm64_raw), "ld_imm64 off");

	mov64_percpu_reg = BPF_MOV64_PERCPU_REG(ld_imm64_raw[0].dst_reg, ld_imm64_raw[0].dst_reg);
	ASSERT_MEMEQ(&insns[idx + 2], &mov64_percpu_reg, insn_sz, "mov64_percpu_reg");

out:
	test_global_percpu_data__destroy(skel);
	free(insns);
}

static void test_global_percpu_data_iter(void)
{
	DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	struct test_global_percpu_data *skel;
	union bpf_iter_link_info linfo = {};
	struct bpf_link *link = NULL;
	int fd, num_cpus, len, err;
	char buf[16];

	num_cpus = libbpf_num_possible_cpus();
	if (!ASSERT_GT(num_cpus, 0, "libbpf_num_possible_cpus"))
		return;

	skel = test_global_percpu_data__open();
	if (!ASSERT_OK_PTR(skel, "test_global_percpu_data__open"))
		return;

	skel->rodata->num_cpus = num_cpus;
	skel->rodata->offsetof_num = offsetof(struct test_global_percpu_data__percpu, struct_data);
	skel->rodata->offsetof_num += sizeof(skel->percpu->struct_data) - sizeof(int);
	skel->rodata->elem_sz = roundup(sizeof(struct test_global_percpu_data__percpu), 8);
	skel->percpu->struct_data.nums[6] = 0xc0de;

	err = test_global_percpu_data__load(skel);
	if (!ASSERT_OK(err, "test_global_percpu_data__load"))
		goto out;

	linfo.map.map_fd = bpf_map__fd(skel->maps.percpu);
	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);
	link = bpf_program__attach_iter(skel->progs.dump_percpu_data, &opts);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach_iter"))
		goto out;

	fd = bpf_iter_create(bpf_link__fd(link));
	if (!ASSERT_GE(fd, 0, "bpf_iter_create"))
		goto out;

	while ((len = read(fd, buf, sizeof(buf))) > 0)
		do { } while (0);
	ASSERT_EQ(len, 0, "read iter");
	ASSERT_TRUE(skel->bss->run_iter, "run_iter");
	ASSERT_EQ(skel->bss->percpu_data_sum, 0xc0de * num_cpus, "percpu_data_sum");

	close(fd);
out:
	bpf_link__destroy(link);
	test_global_percpu_data__destroy(skel);
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
	if (test__start_subtest("verifier_log"))
		test_global_percpu_data_verifier_log();
	if (test__start_subtest("xlated"))
		test_global_percpu_data_xlated();
	if (test__start_subtest("iter"))
		test_global_percpu_data_iter();
}
