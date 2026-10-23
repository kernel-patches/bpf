// SPDX-License-Identifier: GPL-2.0-only
/*
 * Tests for KALLSYMS_QUERY ioctl() on /proc/kallsyms.
 */
#undef NDEBUG
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <linux/fs.h>

#include "kselftest.h"

#define KSYM_NAME_LEN 512

struct kallsyms_query_ext {
	struct kallsyms_query v0;
	__u64 extra;
};

static int do_query(int fd, void *q)
{
	return ioctl(fd, KALLSYMS_QUERY, q) < 0 ? -errno : 0;
}

static struct kallsyms_query sym_query(const char *name)
{
	return (struct kallsyms_query){
		.size = sizeof(struct kallsyms_query),
		.query_flags = KALLSYMS_QUERY_BY_SYMBOL,
		.sym_name_addr = (__u64)(uintptr_t)name,
	};
}

static int query_symbol(int fd, const char *name, struct kallsyms_query *q)
{
	*q = sym_query(name);
	return do_query(fd, q);
}

static int query_addr(int fd, unsigned long long addr, char *buf,
		      size_t buf_sz, struct kallsyms_query *q)
{
	*q = (struct kallsyms_query){
		.size = sizeof(*q),
		.query_flags = KALLSYMS_QUERY_BY_ADDR,
		.sym_name_addr = (__u64)(uintptr_t)buf,
		.sym_addr = addr,
		.sym_name_size = buf_sz,
	};
	return do_query(fd, q);
}

static bool find_vmlinux_symbol(const char *target, unsigned long long *addr_out)
{
	char name[KSYM_NAME_LEN];
	char line[1024];
	char type;
	char mod;
	FILE *f;

	f = fopen("/proc/kallsyms", "r");
	if (!f)
		return false;

	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "%llx %c %511s %c", addr_out, &type, name, &mod) == 3 &&
		    strcmp(name, target) == 0) {
			fclose(f);
			return true;
		}
	}
	fclose(f);
	return false;
}

int main(void)
{
	const char *sym_name = "vfs_read";
	char resolved_name[KSYM_NAME_LEN];
	char long_name[KSYM_NAME_LEN + 1];
	size_t page_size = sysconf(_SC_PAGESIZE);
	unsigned long long exp_addr;
	struct kallsyms_query_ext q1;
	struct kallsyms_query q;
	char *page_buf;
	int err;
	int fd;

	fd = open("/proc/kallsyms", O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		if (errno == ENOENT)
			return KSFT_SKIP;
		ksft_exit_fail_msg("open(/proc/kallsyms) failed: %s\n",
				   strerror(errno));
	}

	if (!find_vmlinux_symbol(sym_name, &exp_addr)) {
		close(fd);
		return KSFT_SKIP;
	}

	/* CASE 1: Valid vmlinux symbol query (or -EPERM when addresses are hidden) */
	err = query_symbol(fd, sym_name, &q);
	if (err == -ENOTTY) {
		close(fd);
		return KSFT_SKIP;
	}
	if (!exp_addr) {
		assert(err == -EPERM);
		close(fd);
		ksft_exit_skip("kallsyms addresses are hidden, only -EPERM checked\n");
	}
	assert(err == 0);
	assert(q.sym_addr == exp_addr);

	/* CASE 2: Missing symbol returns -ENOENT */
	assert(query_symbol(fd, "__nonexistent_kallsyms_symbol__", &q) == -ENOENT);

	/* CASE 3: Empty symbol name returns -EINVAL */
	assert(query_symbol(fd, "", &q) == -EINVAL);

	/* CASE 4: NULL sym_name_addr returns -EFAULT */
	assert(query_symbol(fd, NULL, &q) == -EFAULT);

	/* CASE 5: Symbol name >= KSYM_NAME_LEN returns -ENAMETOOLONG */
	memset(long_name, 'a', KSYM_NAME_LEN);
	long_name[KSYM_NAME_LEN] = '\0';
	assert(query_symbol(fd, long_name, &q) == -ENAMETOOLONG);

	/* CASE 6: Symbol name == KSYM_NAME_LEN - 1 returns -ENOENT */
	long_name[KSYM_NAME_LEN - 1] = '\0';
	assert(query_symbol(fd, long_name, &q) == -ENOENT);

	/* CASE 7: Zero, multiple, or unknown query_flags return -EINVAL */
	q = sym_query(sym_name);
	q.query_flags = 0;
	assert(do_query(fd, &q) == -EINVAL);
	q.query_flags = KALLSYMS_QUERY_BY_SYMBOL | KALLSYMS_QUERY_BY_ADDR;
	assert(do_query(fd, &q) == -EINVAL);
	q.query_flags = 1ULL << 63;
	assert(do_query(fd, &q) == -EINVAL);

	/* CASE 8: Non-zero output fields on input in symbol mode return -EINVAL */
	q = sym_query(sym_name);
	q.sym_addr = 1;
	assert(do_query(fd, &q) == -EINVAL);
	q = sym_query(sym_name);
	q.sym_name_size = 1;
	assert(do_query(fd, &q) == -EINVAL);

	/* CASE 9: size < minimum size returns -EINVAL */
	q = sym_query(sym_name);
	q.size = KALLSYMS_QUERY_SIZE_VER0 - 8;
	assert(do_query(fd, &q) == -EINVAL);

	/* CASE 10: size > PAGE_SIZE returns -E2BIG */
	q = sym_query(sym_name);
	q.size = page_size + 8;
	assert(do_query(fd, &q) == -E2BIG);

	/* CASE 11: Larger extensible struct with zeroed trailing bytes succeeds */
	q1 = (struct kallsyms_query_ext){ .v0 = sym_query(sym_name) };
	q1.v0.size = sizeof(q1);
	assert(do_query(fd, &q1) == 0);
	assert(q1.v0.sym_addr == exp_addr);

	/*
	 * CASE 12: Larger struct with non-zero trailing bytes returns -E2BIG.
	 * Set the last byte of a page-sized struct so that future fields do
	 * not change the result.
	 */
	page_buf = calloc(1, page_size);
	assert(page_buf);
	q = sym_query(sym_name);
	q.size = page_size;
	memcpy(page_buf, &q, sizeof(q));
	page_buf[page_size - 1] = 1;
	assert(do_query(fd, page_buf) == -E2BIG);
	free(page_buf);

	/* CASE 13: Valid address-to-symbol query (exact start + interior offset) */
	memset(resolved_name, 0, sizeof(resolved_name));
	assert(query_addr(fd, exp_addr, resolved_name, sizeof(resolved_name), &q) == 0);
	assert(strcmp(resolved_name, sym_name) == 0);
	assert(q.sym_addr == exp_addr);
	assert(q.sym_name_size == strlen(sym_name) + 1);

	memset(resolved_name, 0, sizeof(resolved_name));
	assert(query_addr(fd, exp_addr + 1, resolved_name, sizeof(resolved_name), &q) == 0);
	assert(strcmp(resolved_name, sym_name) == 0);
	assert(q.sym_addr == exp_addr + 1);
	assert(q.sym_name_size == strlen(sym_name) + 1);

	/* CASE 14: KALLSYMS_QUERY_BY_ADDR with buffer too small returns -ENAMETOOLONG */
	assert(query_addr(fd, exp_addr, resolved_name, strlen(sym_name), &q) == -ENAMETOOLONG);

	/* CASE 15: KALLSYMS_QUERY_BY_ADDR on unmapped address returns -ENOENT */
	assert(query_addr(fd, ~0ULL, resolved_name, sizeof(resolved_name), &q) == -ENOENT);

	/* CASE 16: KALLSYMS_QUERY_BY_ADDR invalid inputs return -EINVAL or -EFAULT */
	assert(query_addr(fd, exp_addr, resolved_name, 0, &q) == -EINVAL);
	assert(query_addr(fd, exp_addr, NULL, sizeof(resolved_name), &q) == -EFAULT);

	close(fd);
	return 0;
}
