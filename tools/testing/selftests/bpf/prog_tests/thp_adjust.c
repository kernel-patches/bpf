// SPDX-License-Identifier: GPL-2.0

#include <sys/mman.h>
#include <test_progs.h>
#include "test_thp_adjust.skel.h"

#define LEN (16 * 1024 * 1024) /* 16MB */
#define THP_ENABLED_FILE "/sys/kernel/mm/transparent_hugepage/enabled"
#define PMD_SIZE_FILE "/sys/kernel/mm/transparent_hugepage/hpage_pmd_size"

static struct test_thp_adjust *skel;
static char old_mode[32];
static long pagesize;

static int thp_mode_save(void)
{
	const char *start, *end;
	char buf[128];
	int fd, err;
	size_t len;

	fd = open(THP_ENABLED_FILE, O_RDONLY);
	if (fd == -1)
		return -1;

	err = read(fd, buf, sizeof(buf) - 1);
	if (err == -1)
		goto close;

	start = strchr(buf, '[');
	end = start ? strchr(start, ']') : NULL;
	if (!start || !end || end <= start) {
		err = -1;
		goto close;
	}

	len = end - start - 1;
	if (len >= sizeof(old_mode))
		len = sizeof(old_mode) - 1;
	strncpy(old_mode, start + 1, len);
	old_mode[len] = '\0';

close:
	close(fd);
	return err;
}

static int thp_mode_set(const char *desired_mode)
{
	int fd, err;

	fd = open(THP_ENABLED_FILE, O_RDWR);
	if (fd == -1)
		return -1;

	err = write(fd, desired_mode, strlen(desired_mode));
	close(fd);
	return err;
}

static int thp_mode_reset(void)
{
	int fd, err;

	fd = open(THP_ENABLED_FILE, O_WRONLY);
	if (fd == -1)
		return -1;

	err = write(fd, old_mode, strlen(old_mode));
	close(fd);
	return err;
}

static char *thp_alloc(void)
{
	char *addr;
	int err, i;

	addr = mmap(NULL, LEN, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
	if (addr == MAP_FAILED)
		return NULL;

	err = madvise(addr, LEN, MADV_HUGEPAGE);
	if (err == -1)
		goto unmap;

	/* Accessing a single byte within a page is sufficient to trigger a page fault. */
	for (i = 0; i < LEN; i += pagesize)
		addr[i] = 1;
	return addr;

unmap:
	munmap(addr, LEN);
	return NULL;
}

static void thp_free(char *ptr)
{
	munmap(ptr, LEN);
}

static int get_pmd_order(void)
{
	ssize_t bytes_read, size;
	int fd, order, ret = -1;
	char buf[64], *endptr;

	fd = open(PMD_SIZE_FILE, O_RDONLY);
	if (fd < 0)
		return -1;

	bytes_read = read(fd, buf, sizeof(buf) - 1);
	if (bytes_read <= 0)
		goto close_fd;

	/* Remove potential newline character */
	if (buf[bytes_read - 1] == '\n')
		buf[bytes_read - 1] = '\0';

	size = strtoul(buf, &endptr, 10);
	if (endptr == buf || *endptr != '\0')
		goto close_fd;
	if (size % pagesize != 0)
		goto close_fd;
	ret = size / pagesize;
	if ((ret & (ret - 1)) == 0) {
		order = 0;
		while (ret > 1) {
			ret >>= 1;
			order++;
		}
		ret = order;
	}

close_fd:
	close(fd);
	return ret;
}

static int get_thp_eligible(pid_t pid, unsigned long addr)
{
	int this_vma = 0, eligible = -1;
	unsigned long start, end;
	char smaps_path[64];
	FILE *smaps_file;
	char line[4096];

	snprintf(smaps_path, sizeof(smaps_path), "/proc/%d/smaps", pid);
	smaps_file = fopen(smaps_path, "r");
	if (!smaps_file)
		return -1;

	while (fgets(line, sizeof(line), smaps_file)) {
		if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
			/* addr is monotonic */
			if (addr < start)
				break;
			this_vma = (addr >= start && addr < end) ? 1 : 0;
			continue;
		}

		if (!this_vma)
			continue;

		if (strstr(line, "THPeligible:")) {
			sscanf(line, "THPeligible: %d", &eligible);
			break;
		}
	}

	fclose(smaps_file);
	return eligible;
}

static void subtest_thp_eligible(void)
{
	struct bpf_link *ops_link;
	int elighble;
	char *ptr;

	ops_link = bpf_map__attach_struct_ops(skel->maps.thp_eligible_ops);
	if (!ASSERT_OK_PTR(ops_link, "attach struct_ops"))
		return;

	ptr = thp_alloc();
	if (!ASSERT_OK_PTR(ptr, "THP alloc"))
		goto detach;

	elighble = get_thp_eligible(getpid(), (unsigned long)ptr);
	ASSERT_EQ(elighble, 0, "THPeligible");

	thp_free(ptr);
detach:
	bpf_link__destroy(ops_link);
}

static void subtest_thp_policy_update(void)
{
	struct bpf_link *old_link, *new_link;
	int elighble, err, pid;
	char *ptr;

	pid = getpid();
	ptr = thp_alloc();

	old_link = bpf_map__attach_struct_ops(skel->maps.thp_eligible_ops);
	if (!ASSERT_OK_PTR(old_link, "attach_old_link"))
		goto free;

	elighble = get_thp_eligible(pid, (unsigned long)ptr);
	ASSERT_EQ(elighble, 0, "THPeligible");

	/* Attach multi BPF-THP to a single process is rejected. */
	new_link = bpf_map__attach_struct_ops(skel->maps.thp_eligible_ops2);
	if (!ASSERT_NULL(new_link, "attach_new_link"))
		goto destory_old;
	ASSERT_EQ(errno, EBUSY, "attach_new_link");

	elighble = get_thp_eligible(pid, (unsigned long)ptr);
	ASSERT_EQ(elighble, 0, "THPeligible");

	err = bpf_link__update_map(old_link, skel->maps.thp_eligible_ops2);
	ASSERT_EQ(err, 0, "update_old_link");

	elighble = get_thp_eligible(pid, (unsigned long)ptr);
	ASSERT_EQ(elighble, 1, "THPeligible");

	/* Per process prog can't be update by a global prog */
	err = bpf_link__update_map(old_link, skel->maps.swap_ops);
	ASSERT_EQ(err, -EINVAL, "update_old_link");

destory_old:
	bpf_link__destroy(old_link);
free:
	thp_free(ptr);
}

static void subtest_thp_global_policy(void)
{
	struct bpf_link *local_link, *global_link;
	int err;

	local_link = bpf_map__attach_struct_ops(skel->maps.thp_eligible_ops);
	if (!ASSERT_OK_PTR(local_link, "attach_local_link"))
		return;

	/* global prog can be attached even if there is a local prog */
	global_link = bpf_map__attach_struct_ops(skel->maps.swap_ops);
	if (!ASSERT_OK_PTR(global_link, "attach_global_link")) {
		bpf_link__destroy(local_link);
		return;
	}

	bpf_link__destroy(local_link);

	/* local prog can't be attaached if there is a global prog */
	local_link = bpf_map__attach_struct_ops(skel->maps.thp_eligible_ops);
	if (!ASSERT_NULL(local_link, "attach_new_link"))
		goto destory_global;
	ASSERT_EQ(errno, EBUSY, "attach_new_link");

	/* global prog can't be updated by a local prog */
	err = bpf_link__update_map(global_link, skel->maps.thp_eligible_ops);
	ASSERT_EQ(err, -EINVAL, "update_old_link");

destory_global:
	bpf_link__destroy(global_link);
}

static int thp_adjust_setup(void)
{
	int err = -1, pmd_order;

	pagesize = sysconf(_SC_PAGESIZE);
	pmd_order = get_pmd_order();
	if (!ASSERT_NEQ(pmd_order, -1, "get_pmd_order"))
		return -1;

	if (!ASSERT_NEQ(thp_mode_save(), -1, "THP mode save"))
		return -1;
	if (!ASSERT_GE(thp_mode_set("madvise"), 0, "THP mode set"))
		return -1;

	skel = test_thp_adjust__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		goto thp_reset;

	skel->bss->pmd_order = pmd_order;
	skel->struct_ops.thp_eligible_ops->pid = getpid();
	skel->struct_ops.thp_eligible_ops2->pid = getpid();
	/* swap_ops is a global prog since its pid is not set. */

	err = test_thp_adjust__load(skel);
	if (!ASSERT_OK(err, "load"))
		goto destroy;
	return 0;

destroy:
	test_thp_adjust__destroy(skel);
thp_reset:
	ASSERT_GE(thp_mode_reset(), 0, "THP mode reset");
	return err;
}

static void thp_adjust_destroy(void)
{
	test_thp_adjust__destroy(skel);
	ASSERT_GE(thp_mode_reset(), 0, "THP mode reset");
}

void test_thp_adjust(void)
{
	if (thp_adjust_setup() == -1)
		return;

	if (test__start_subtest("thp_eligible"))
		subtest_thp_eligible();
	if (test__start_subtest("policy_update"))
		subtest_thp_policy_update();
	if (test__start_subtest("global_policy"))
		subtest_thp_global_policy();

	thp_adjust_destroy();
}
