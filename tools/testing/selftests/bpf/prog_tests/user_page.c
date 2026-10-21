// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include <sys/mman.h>
#include <sys/personality.h>
#include <unistd.h>

#include "user_page.skel.h"

enum {
	USER_PAGE_ALLOC = 1,
	USER_PAGE_EXEC = 2,
	USER_PAGE_EXEC_ONLY = 3,
};

static noinline void user_page_trigger(void)
{
	asm volatile ("");
}

static bool check_user_page_vma(void *addr, long size, const char *perms)
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

static bool alloc_user_pages(struct user_page *skel, unsigned long nr_pages,
			     long *addr)
{
	skel->bss->nr_pages = nr_pages;
	skel->bss->action = USER_PAGE_ALLOC;
	user_page_trigger();
	if (!ASSERT_GE(skel->bss->user_addr, 0, "user_addr"))
		return false;

	*addr = skel->bss->user_addr;
	return true;
}

static void test_allocations(struct user_page *skel)
{
	void *pages[2] = { MAP_FAILED, MAP_FAILED };
	long page_size = sysconf(_SC_PAGESIZE);
	const unsigned long nr_pages = 3;
	long addr;
	int i;

	for (i = 0; i < ARRAY_SIZE(pages); i++) {
		if (!alloc_user_pages(skel, nr_pages, &addr))
			goto out;
		pages[i] = (void *)addr;
	}

	/* Back-to-back allocations must remain individual VMAs. */
	for (i = 0; i < ARRAY_SIZE(pages); i++) {
		if (!check_user_page_vma(pages[i], page_size * nr_pages, NULL))
			break;
	}

out:
	for (i = 0; i < ARRAY_SIZE(pages); i++)
		if (pages[i] != MAP_FAILED)
			munmap(pages[i], page_size * nr_pages);
}

static void test_reallocate_after_unmap(struct user_page *skel)
{
	long page_size = sysconf(_SC_PAGESIZE);
	long addr = -1;

	if (!alloc_user_pages(skel, 1, &addr))
		goto out;

	if (!ASSERT_OK(munmap((void *)addr, page_size), "munmap"))
		goto out;

	addr = -1;
	alloc_user_pages(skel, 1, &addr);

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

	skel->bss->action = USER_PAGE_ALLOC;
	skel->bss->nr_pages = 1;
	user_page_trigger();
	if (!ASSERT_GE(skel->bss->user_addr, 0, "read_implies_exec_alloc_ret"))
		goto out;
	addr = skel->bss->user_addr;
	check_user_page_vma((void *)addr, page_size, "rw-p");

out:
	if (addr >= 0)
		munmap((void *)addr, page_size);
	ASSERT_EQ(personality(old_personality), set_personality,
		  "restore_personality");
}

static void test_execute_user_page(struct user_page *skel)
{
	long page_size = sysconf(_SC_PAGESIZE);
	long addr = -1;

#ifndef __x86_64__
	test__skip();
	return;
#endif

	if (!alloc_user_pages(skel, 1, &addr))
		return;

	skel->bss->exec_addr = addr;
	skel->bss->action = USER_PAGE_EXEC;
	user_page_trigger();
	if (!ASSERT_EQ(skel->bss->write_ret, 0, "exec_write_ret") ||
	    !ASSERT_EQ(skel->bss->exec_ret, 0, "exec_ret"))
		goto out;

	ASSERT_EQ(((int (*)(void))addr)(), 42, "execute_user_page");

out:
	if (addr >= 0)
		munmap((void *)addr, page_size);
}

static void test_partial_exec(struct user_page *skel)
{
	long page_size = sysconf(_SC_PAGESIZE);
	long addr = -1;

	if (!alloc_user_pages(skel, 3, &addr))
		return;

	skel->bss->exec_addr = addr + page_size;
	skel->bss->action = USER_PAGE_EXEC_ONLY;
	user_page_trigger();
	if (!ASSERT_OK(skel->bss->exec_ret, "middle_page_exec_ret") ||
	    !check_user_page_vma((void *)(addr + 0 * page_size), page_size, "rw-p") ||
	    !check_user_page_vma((void *)(addr + 1 * page_size), page_size, "r-xp") ||
	    !check_user_page_vma((void *)(addr + 2 * page_size), page_size, "rw-p"))
		goto out;

	skel->bss->exec_addr = addr + 2 * page_size;
	user_page_trigger();
	if (!ASSERT_OK(skel->bss->exec_ret, "last_page_exec_ret"))
		goto out;

	check_user_page_vma((void *)(addr + 2 * page_size), page_size, "r-xp");

out:
	if (addr >= 0)
		munmap((void *)addr, page_size * 3);
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
	if (test__start_subtest("reallocate_after_unmap"))
		test_reallocate_after_unmap(skel);
	if (test__start_subtest("read_implies_exec"))
		test_read_implies_exec(skel);
	if (test__start_subtest("execute_user_page"))
		test_execute_user_page(skel);
	if (test__start_subtest("partial_exec"))
		test_partial_exec(skel);

out:
	user_page__destroy(skel);
}
