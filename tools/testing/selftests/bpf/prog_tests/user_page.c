// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include <sys/mman.h>
#include <sys/personality.h>
#include <unistd.h>

#include "user_page.skel.h"

enum {
	USER_MEM_MAP = 1,
	USER_MEM_COPY = 2,
	USER_MEM_BAD_COPY = 3,
	USER_MEM_BAD_COPY_FLAGS = 4,
	USER_MEM_UNMAP = 5,
};

static noinline void user_page_trigger(void)
{
	asm volatile ("");
}

static bool find_user_page_vma(void *addr, long size, const char *perms)
{
	unsigned long start, end;
	bool found = false;
	char vma_perms[5];
	char line[512];
	FILE *maps;

	maps = fopen("/proc/self/maps", "r");
	if (!ASSERT_OK_PTR(maps, "open_maps"))
		return false;

	while (fgets(line, sizeof(line), maps)) {
		if (sscanf(line, "%lx-%lx %4s", &start, &end, vma_perms) != 3 ||
		    (unsigned long)addr < start || (unsigned long)addr >= end)
			continue;
		found = ASSERT_EQ(start, (unsigned long)addr, "vma_start") &&
			ASSERT_EQ(end - start, size, "vma_size") &&
			(!perms || ASSERT_STREQ(vma_perms, perms, "vma_perms"));
		break;
	}
	fclose(maps);
	return ASSERT_TRUE(found, "user_page_vma");
}

static bool alloc_user_mapping(struct user_page *skel, unsigned long len,
			       unsigned long prot, long *addr)
{
	skel->bss->map_len = len;
	skel->bss->map_prot = prot;
	skel->bss->action = USER_MEM_MAP;
	user_page_trigger();
	if (!ASSERT_GE(skel->bss->user_addr, 0, "user_addr"))
		return false;

	*addr = skel->bss->user_addr;
	return true;
}

static void test_allocations(struct user_page *skel)
{
	void *maps[2] = { MAP_FAILED, MAP_FAILED };
	long page_size = sysconf(_SC_PAGESIZE);
	int i;

	for (i = 0; i < ARRAY_SIZE(maps); i++) {
		long addr = -1;

		if (!alloc_user_mapping(skel, page_size * 2,
					PROT_READ | PROT_WRITE, &addr))
			goto out;
		maps[i] = (void *)addr;
	}

	for (i = 0; i < ARRAY_SIZE(maps); i++) {
		if (!find_user_page_vma(maps[i], page_size * 2, "rw-p"))
			break;
	}

out:
	for (i = 0; i < ARRAY_SIZE(maps); i++)
		if (maps[i] != MAP_FAILED)
			munmap(maps[i], page_size * 2);
}

static void test_faultable_copy(struct user_page *skel)
{
	static const char expected[] = "fault-enabled BPF write";
	long page_size = sysconf(_SC_PAGESIZE);
	long addr = -1;

	if (!alloc_user_mapping(skel, page_size, PROT_READ | PROT_WRITE, &addr))
		return;

	skel->bss->user_addr = addr;
	skel->bss->action = USER_MEM_COPY;
	user_page_trigger();
	if (!ASSERT_EQ(skel->bss->op_ret, 0, "copy_ret"))
		goto out;
	ASSERT_EQ(memcmp((void *)addr, expected, sizeof(expected)), 0, "copied_data");

out:
	if (addr >= 0)
		munmap((void *)addr, page_size);
}

static void test_read_implies_exec(struct user_page *skel)
{
	long page_size = sysconf(_SC_PAGESIZE);
	long addr = -1;
	int old_personality, set_personality;

	old_personality = personality(0xffffffffUL);
	if (!ASSERT_NEQ(old_personality, -1, "get_personality"))
		return;
	set_personality = old_personality | READ_IMPLIES_EXEC;
	if (!ASSERT_NEQ(personality(set_personality), -1, "set_personality"))
		return;

	if (alloc_user_mapping(skel, page_size, PROT_READ | PROT_WRITE, &addr)) {
		find_user_page_vma((void *)addr, page_size, "rw-p");
		errno = 0;
		ASSERT_EQ(mprotect((void *)addr, page_size, PROT_READ | PROT_EXEC),
			  -1, "enable_exec");
		ASSERT_EQ(errno, EACCES, "enable_exec_errno");
	}

	if (addr >= 0)
		munmap((void *)addr, page_size);
	ASSERT_EQ(personality(old_personality), set_personality,
		  "restore_personality");
}

static void test_bpf_unmap(struct user_page *skel)
{
	long page_size = sysconf(_SC_PAGESIZE);
	long addr = -1;
	unsigned char vec;

	if (!alloc_user_mapping(skel, page_size, PROT_READ | PROT_WRITE, &addr))
		return;

	skel->bss->user_addr = addr;
	skel->bss->map_len = page_size;
	skel->bss->action = USER_MEM_UNMAP;
	user_page_trigger();
	ASSERT_EQ(skel->bss->op_ret, 0, "bpf_unmap_ret");
	errno = 0;
	ASSERT_EQ(mincore((void *)addr, page_size, &vec), -1, "mapping_gone");
	ASSERT_EQ(errno, ENOMEM, "mapping_gone_errno");
	addr = -1;
}

static void test_invalid_operations(struct user_page *skel)
{
	long page_size = sysconf(_SC_PAGESIZE);

	skel->bss->action = USER_MEM_MAP;
	skel->bss->map_len = 0;
	skel->bss->map_prot = PROT_READ | PROT_WRITE;
	user_page_trigger();
	ASSERT_EQ(skel->bss->user_addr, -EINVAL, "zero_len");

	skel->bss->map_len = page_size;
	skel->bss->map_prot = PROT_READ | PROT_EXEC;
	user_page_trigger();
	ASSERT_EQ(skel->bss->user_addr, -EINVAL, "exec_prot");

	skel->bss->map_prot = PROT_NONE;
	user_page_trigger();
	ASSERT_EQ(skel->bss->user_addr, -EINVAL, "unsupported_prot");

	skel->bss->action = USER_MEM_BAD_COPY;
	user_page_trigger();
	ASSERT_EQ(skel->bss->op_ret, -EFAULT, "bad_copy");

	skel->bss->user_addr = 1;
	skel->bss->copy_flags = 1;
	skel->bss->action = USER_MEM_BAD_COPY_FLAGS;
	user_page_trigger();
	ASSERT_EQ(skel->bss->op_ret, -EINVAL, "bad_copy_flags");
}

void test_user_page(void)
{
	struct user_page *skel;

	skel = user_page__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	skel->bss->monitored_pid = getpid();
	if (!ASSERT_OK(user_page__attach(skel), "attach"))
		goto out;

	if (test__start_subtest("allocations"))
		test_allocations(skel);
	if (test__start_subtest("faultable_copy"))
		test_faultable_copy(skel);
	if (test__start_subtest("read_implies_exec"))
		test_read_implies_exec(skel);
	if (test__start_subtest("bpf_unmap"))
		test_bpf_unmap(skel);
	if (test__start_subtest("invalid_operations"))
		test_invalid_operations(skel);

out:
	user_page__destroy(skel);
}
