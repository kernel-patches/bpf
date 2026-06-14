// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include <bpf/bpf.h>
#include <linux/filter.h>
#include <sys/mman.h>
#include <sys/user.h>
#ifndef PAGE_SIZE
#include <unistd.h>
#define PAGE_SIZE getpagesize()
#endif

static int create_arena(void)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts,
		    .map_flags = BPF_F_MMAPABLE,
	);

	return bpf_map_create(BPF_MAP_TYPE_ARENA, "arena", 0, 0, 1, &opts);
}

static int load_direct_value_prog(int map_fd, int off)
{
	struct bpf_insn insns[] = {
		BPF_LD_MAP_VALUE(BPF_REG_1, map_fd, off),
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};

	return bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, NULL, "GPL",
			     insns, ARRAY_SIZE(insns), NULL);
}

static void test_direct_value_boundary(void)
{
	void *area = MAP_FAILED;
	int map_fd, prog_fd;

	map_fd = create_arena();
	if (!ASSERT_OK_FD(map_fd, "create_arena"))
		return;

	area = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
	if (!ASSERT_NEQ(area, MAP_FAILED, "arena_mmap"))
		goto out;

	prog_fd = load_direct_value_prog(map_fd, PAGE_SIZE - 1);
	if (ASSERT_OK_FD(prog_fd, "last_valid_byte"))
		close(prog_fd);

	prog_fd = load_direct_value_prog(map_fd, PAGE_SIZE);
	if (!ASSERT_LT(prog_fd, 0, "one_past_end"))
		close(prog_fd);

out:
	if (area != MAP_FAILED)
		munmap(area, PAGE_SIZE);
	close(map_fd);
}

void test_arena_direct_value(void)
{
	if (test__start_subtest("direct_value_boundary"))
		test_direct_value_boundary();
}
