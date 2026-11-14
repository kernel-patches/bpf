// SPDX-License-Identifier: GPL-2.0-only
/* Tests for the KALLSYMS_QUERY_* ioctls on /proc/kallsyms */
#undef NDEBUG
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <linux/fs.h>

#include "kselftest.h"

#define PTR(p) ((__u64)(uintptr_t)(p))
#define PREFIX "vfs_"

static char name_buf[512];
static char mod_buf[64];

/* Expected values, from the /proc/kallsyms text */
static struct {
	unsigned long long vfs_read_addr;
	bool vfs_read_found;
	unsigned int prefix_cnt;	/* vmlinux names with PREFIX */
	unsigned long long mod_addr;	/* module text symbol, or 0 */
	char mod[64];
} ref;

static void scan_text(void)
{
	FILE *f = fopen("/proc/kallsyms", "r");
	unsigned long long addr;
	char line[1024];
	bool plain_name;
	char name[513];
	char mod[64];
	bool vmlinux;
	bool module;
	bool text;
	char type;
	int n;

	assert(f);
	while (fgets(line, sizeof(line), f)) {
		/* 3 fields for vmlinux, 4 if the line ends with [module] */
		n = sscanf(line, "%llx %c %512s [%63[^]]]",
			   &addr, &type, name, mod);
		/* A longer name would be cut and parsed as vmlinux */
		assert(n >= 3 && strlen(name) < sizeof(name) - 1);
		vmlinux = n == 3;
		module = n == 4 && strcmp(mod, "bpf") &&
			 strncmp(mod, "__builtin__", strlen("__builtin__"));
		text = type == 't' || type == 'T';
		plain_name = name[0] != '.' && name[0] != '$';

		if (vmlinux) {
			if (!strncmp(name, PREFIX, strlen(PREFIX)))
				ref.prefix_cnt++;
			if (!ref.vfs_read_found && !strcmp(name, "vfs_read")) {
				ref.vfs_read_addr = addr;
				ref.vfs_read_found = true;
			}
		} else if (module && text && plain_name && !ref.mod_addr) {
			ref.mod_addr = addr;
			strcpy(ref.mod, mod);
		}
	}
	fclose(f);
}

static struct kallsyms_query_sym bufs(size_t name_len, size_t mod_len)
{
	return (struct kallsyms_query_sym){
		.sym_name = name_len ? PTR(name_buf) : 0,
		.sym_name_len = name_len,
		.sym_module = mod_len ? PTR(mod_buf) : 0,
		.sym_module_len = mod_len,
	};
}

static struct kallsyms_query_by_name name_q(const char *name, const char *mod,
					    struct kallsyms_query_sym *sym)
{
	return (struct kallsyms_query_by_name){
		.size = sizeof(struct kallsyms_query_by_name),
		.query_name = PTR(name),
		.module_filter = PTR(mod),
		.sym = PTR(sym),
		.sym_struct_size = sizeof(*sym),
	};
}

static struct kallsyms_query_by_addr addr_q(unsigned long long addr,
					    struct kallsyms_query_sym *sym)
{
	return (struct kallsyms_query_by_addr){
		.size = sizeof(struct kallsyms_query_by_addr),
		.query_addr = addr,
		.sym = PTR(sym),
		.sym_struct_size = sizeof(*sym),
	};
}

static int by_name(int fd, void *q)
{
	return ioctl(fd, KALLSYMS_QUERY_BY_NAME, q) ? -errno : 0;
}

static int by_addr(int fd, void *q)
{
	return ioctl(fd, KALLSYMS_QUERY_BY_ADDR, q) ? -errno : 0;
}

int main(void)
{
	struct {
		struct kallsyms_query_by_name q;
		__u64 extra;
	} qx = {};
	struct {
		struct kallsyms_query_sym s;
		__u64 extra;
	} sx = {};
	struct kallsyms_query_by_addr qa;
	struct kallsyms_query_by_name q;
	struct kallsyms_query_sym sym;
	unsigned int cnt = 0;
	__u64 first_pos = 0;
	char name[512];
	__u64 size;
	__u64 len;
	int err;
	int fd;

	fd = open("/proc/kallsyms", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		ksft_exit_skip("open(/proc/kallsyms): %s\n", strerror(errno));
	scan_text();
	if (!ref.vfs_read_found)
		ksft_exit_skip("vfs_read is not in /proc/kallsyms\n");

	/* Exact name in vmlinux, with name and module buffers */
	sym = bufs(sizeof(name_buf), sizeof(mod_buf));
	q = name_q("vfs_read", "vmlinux", &sym);
	err = by_name(fd, &q);
	if (err == -ENOTTY)
		ksft_exit_skip("KALLSYMS_QUERY_BY_NAME is not supported\n");
	if (!ref.vfs_read_addr) {
		qa = addr_q(0, &sym);
		assert(err == -EPERM && by_addr(fd, &qa) == -EPERM);
		ksft_exit_skip("kallsyms addresses are hidden\n");
	}
	assert(!err);
	assert(sym.sym_addr == ref.vfs_read_addr && sym.sym_size > 0);
	assert(!strcmp(name_buf, "vfs_read"));
	assert(sym.sym_name_len == sizeof("vfs_read"));
	assert(!mod_buf[0] && sym.sym_module_len == 1);
	size = sym.sym_size;

	/* Prefix: one match per call with pos + 1, until -ENOENT */
	q = name_q(PREFIX, "vmlinux", &sym);
	q.query_flags = KALLSYMS_QUERY_NAME_PREFIX;
	sym = bufs(sizeof(name_buf), 0);
	while (!(err = by_name(fd, &q))) {
		assert(!strncmp(name_buf, PREFIX, strlen(PREFIX)));
		if (!cnt++)
			first_pos = q.pos;
		sym = bufs(sizeof(name_buf), 0);
		q.pos++;
	}
	assert(err == -ENOENT && cnt == ref.prefix_cnt);

	/* -ENAMETOOLONG sets pos and both sizes; a retry succeeds */
	sym = bufs(1, 2);
	q.pos = 0;
	assert(by_name(fd, &q) == -ENAMETOOLONG && q.pos == first_pos);
	assert(sym.sym_module_len == 1);
	len = sym.sym_name_len;
	sym.sym_name_len = sizeof(name_buf);
	assert(by_name(fd, &q) == 0 && q.pos == first_pos);
	assert(sym.sym_name_len == len && strlen(name_buf) + 1 == len);

	/* No match */
	sym = bufs(0, 0);
	q = name_q("__no_such_symbol__", NULL, &sym);
	assert(by_name(fd, &q) == -ENOENT);

	/* BY_ADDR inside vfs_read */
	sym = bufs(sizeof(name_buf), 0);
	qa = addr_q(ref.vfs_read_addr + 1, &sym);
	assert(by_addr(fd, &qa) == 0 && !strcmp(name_buf, "vfs_read"));
	assert(sym.sym_addr == ref.vfs_read_addr && sym.sym_size == size);

	sym = bufs(0, 0);
	qa = addr_q(~0ULL, &sym);
	assert(by_addr(fd, &qa) == -ENOENT);

	/* Module symbol: BY_ADDR and BY_NAME with module_filter agree */
	if (ref.mod_addr) {
		bool found = false;

		sym = bufs(sizeof(name_buf), sizeof(mod_buf));
		qa = addr_q(ref.mod_addr, &sym);
		assert(by_addr(fd, &qa) == 0 && sym.sym_addr == ref.mod_addr);
		assert(!strcmp(mod_buf, ref.mod));
		strcpy(name, name_buf);
		size = sym.sym_size;

		q = name_q(name, ref.mod, &sym);
		sym = bufs(0, sizeof(mod_buf));
		while (!(err = by_name(fd, &q))) {
			assert(!strcmp(mod_buf, ref.mod));
			if (sym.sym_addr == ref.mod_addr) {
				assert(sym.sym_size == size);
				found = true;
			}
			sym = bufs(0, sizeof(mod_buf));
			q.pos++;
		}
		assert(err == -ENOENT && found);
	}

	/* Larger structs with a zero tail are accepted */
	qx.q = name_q("vfs_read", NULL, &sx.s);
	qx.q.size = sizeof(qx);
	qx.q.sym_struct_size = sizeof(sx);
	assert(by_name(fd, &qx) == 0 && sx.s.sym_addr == ref.vfs_read_addr);

	/* Unknown flags and mismatched buffer pointer/length */
	sym = bufs(0, 0);
	q = name_q("vfs_read", NULL, &sym);
	q.query_flags = 1ULL << 63;
	assert(by_name(fd, &q) == -EINVAL);
	qa = addr_q(ref.vfs_read_addr, &sym);
	qa.query_flags = 1;
	assert(by_addr(fd, &qa) == -EINVAL);
	sym = (struct kallsyms_query_sym){ .sym_name = PTR(name_buf) };
	q = name_q("vfs_read", NULL, &sym);
	assert(by_name(fd, &q) == -EINVAL);
	sym = (struct kallsyms_query_sym){ .sym_module_len = sizeof(mod_buf) };
	assert(by_name(fd, &q) == -EINVAL);

	close(fd);
	return 0;
}
