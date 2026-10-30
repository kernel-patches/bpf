// SPDX-License-Identifier: GPL-2.0
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <unistd.h>
#include <linux/perf_event.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include "trace_helpers.h"
#include <linux/limits.h>
#include <libelf.h>
#include <gelf.h>
#include "bpf/hashmap.h"
#include "bpf/libbpf_internal.h"
#include "bpf_util.h"

#define TRACEFS		"/sys/kernel/tracing"
#define TRACEFS_PIPE	TRACEFS "/trace_pipe"
#define DEBUGFS		"/sys/kernel/debug/tracing"
#define DEBUGFS_PIPE	DEBUGFS "/trace_pipe"

#define CHUNK_SIZE	128

static struct ksyms *ksyms;
static pthread_mutex_t ksyms_mutex = PTHREAD_MUTEX_INITIALIZER;

static int ksyms__add_symbol(struct ksyms *ksyms, const char *name,
			     unsigned long addr)
{
	void *tmp;

	tmp = strdup(name);
	if (!tmp)
		return -ENOMEM;
	ksyms->syms[ksyms->sym_cnt].addr = addr;
	ksyms->syms[ksyms->sym_cnt].name = tmp;
	ksyms->sym_cnt++;
	return 0;
}

void free_kallsyms_local(struct ksyms *ksyms)
{
	unsigned int i;

	if (!ksyms)
		return;

	free(ksyms->filtered_syms);

	if (!ksyms->syms) {
		free(ksyms);
		return;
	}

	for (i = 0; i < ksyms->sym_cnt; i++)
		free(ksyms->syms[i].name);
	free(ksyms->syms);
	free(ksyms);
}

static struct ksyms *load_kallsyms_local_common(ksym_cmp_t cmp_cb)
{
	FILE *f;
	char func[256], buf[256];
	char symbol;
	void *addr;
	int ret;
	struct ksyms *ksyms;

	f = fopen("/proc/kallsyms", "r");
	if (!f)
		return NULL;

	ksyms = calloc(1, sizeof(struct ksyms));
	if (!ksyms) {
		fclose(f);
		return NULL;
	}

	while (fgets(buf, sizeof(buf), f)) {
		if (sscanf(buf, "%p %c %s", &addr, &symbol, func) != 3)
			break;
		if (!addr)
			continue;

		ret = libbpf_ensure_mem((void **) &ksyms->syms, &ksyms->sym_cap,
					sizeof(struct ksym), ksyms->sym_cnt + 1);
		if (ret)
			goto error;
		ret = ksyms__add_symbol(ksyms, func, (unsigned long)addr);
		if (ret)
			goto error;
	}
	fclose(f);
	qsort(ksyms->syms, ksyms->sym_cnt, sizeof(struct ksym), cmp_cb);
	return ksyms;

error:
	fclose(f);
	free_kallsyms_local(ksyms);
	return NULL;
}

static int ksym_cmp(const void *p1, const void *p2)
{
	return ((struct ksym *)p1)->addr - ((struct ksym *)p2)->addr;
}

struct ksyms *load_kallsyms_local(void)
{
	return load_kallsyms_local_common(ksym_cmp);
}

struct ksyms *load_kallsyms_custom_local(ksym_cmp_t cmp_cb)
{
	return load_kallsyms_local_common(cmp_cb);
}

int load_kallsyms(void)
{
	pthread_mutex_lock(&ksyms_mutex);
	if (!ksyms)
		ksyms = load_kallsyms_local();
	pthread_mutex_unlock(&ksyms_mutex);
	return ksyms ? 0 : 1;
}

struct ksym *ksym_search_local(struct ksyms *ksyms, long key)
{
	int start = 0, end = ksyms->sym_cnt;
	int result;

	/* kallsyms not loaded. return NULL */
	if (ksyms->sym_cnt <= 0)
		return NULL;

	while (start < end) {
		size_t mid = start + (end - start) / 2;

		result = key - ksyms->syms[mid].addr;
		if (result < 0)
			end = mid;
		else if (result > 0)
			start = mid + 1;
		else
			return &ksyms->syms[mid];
	}

	if (start >= 1 && ksyms->syms[start - 1].addr < key &&
	    key < ksyms->syms[start].addr)
		/* valid ksym */
		return &ksyms->syms[start - 1];

	/* out of range. return _stext */
	return &ksyms->syms[0];
}

struct ksym *search_kallsyms_custom_local(struct ksyms *ksyms, const void *p,
					  ksym_search_cmp_t cmp_cb)
{
	int start = 0, mid, end = ksyms->sym_cnt;
	struct ksym *ks;
	int result;

	while (start < end) {
		mid = start + (end - start) / 2;
		ks = &ksyms->syms[mid];
		result = cmp_cb(p, ks);
		if (result < 0)
			end = mid;
		else if (result > 0)
			start = mid + 1;
		else
			return ks;
	}

	return NULL;
}

struct ksym *ksym_search(long key)
{
	if (!ksyms)
		return NULL;
	return ksym_search_local(ksyms, key);
}

long ksym_get_addr_local(struct ksyms *ksyms, const char *name)
{
	int i;

	for (i = 0; i < ksyms->sym_cnt; i++) {
		if (strcmp(ksyms->syms[i].name, name) == 0)
			return ksyms->syms[i].addr;
	}

	return 0;
}

long ksym_get_addr(const char *name)
{
	if (!ksyms)
		return 0;
	return ksym_get_addr_local(ksyms, name);
}

/* open kallsyms and read symbol addresses on the fly. Without caching all symbols,
 * this is faster than load + find.
 */
int kallsyms_find(const char *sym, unsigned long long *addr)
{
	char type, name[500], *match;
	unsigned long long value;
	int err = 0;
	FILE *f;

	f = fopen("/proc/kallsyms", "r");
	if (!f)
		return -EINVAL;

	while (fscanf(f, "%llx %c %499s%*[^\n]\n", &value, &type, name) > 0) {
		/* If CONFIG_LTO_CLANG_THIN is enabled, static variable/function
		 * symbols could be promoted to global due to cross-file inlining.
		 * For such cases, clang compiler will add .llvm.<hash> suffix
		 * to those symbols to avoid potential naming conflict.
		 * Let us ignore .llvm.<hash> suffix during symbol comparison.
		 */
		if (type == 'd') {
			match = strstr(name, ".llvm.");
			if (match)
				*match = '\0';
		}
		if (strcmp(name, sym) == 0) {
			*addr = value;
			goto out;
		}
	}
	err = -ENOENT;

out:
	fclose(f);
	return err;
}

unsigned long long module_get_base_addr(const char *module)
{
	unsigned long long addr, base_addr = 0;
	char name[500];
	FILE *f;

	f = fopen("/proc/modules", "r");
	if (!f)
		return 0;

	while (fscanf(f, "%499s %*s %*s %*s %*s 0x%llx", name, &addr) == 2) {
		if (strcmp(module, name) == 0) {
			base_addr = addr;
			break;
		}
	}
	fclose(f);
	return base_addr;
}

unsigned long long module_get_base_addr_sec(const char *module, const char *sec)
{
	unsigned long long addr = 0;
	char *path;
	FILE *f;

	if (asprintf(&path, "/sys/module/%s/sections/%s", module, sec) < 0)
		return 0;
	f = fopen(path, "r");
	free(path);
	if (!f)
		return 0;

	if (fscanf(f, "%llx", &addr) != 1)
		addr = 0;
	fclose(f);
	return addr;
}

#ifdef PROCMAP_QUERY
int env_verbosity __weak = 0;

static int procmap_query(int fd, const void *addr, __u32 query_flags, size_t *start, size_t *offset, int *flags)
{
	char path_buf[PATH_MAX], build_id_buf[20];
	struct procmap_query q;
	int err;

	memset(&q, 0, sizeof(q));
	q.size = sizeof(q);
	q.query_flags = query_flags;
	q.query_addr = (__u64)addr;
	q.vma_name_addr = (__u64)path_buf;
	q.vma_name_size = sizeof(path_buf);
	q.build_id_addr = (__u64)build_id_buf;
	q.build_id_size = sizeof(build_id_buf);

	err = ioctl(fd, PROCMAP_QUERY, &q);
	if (err < 0) {
		err = -errno;
		if (err == -ENOTTY)
			return -EOPNOTSUPP; /* ioctl() not implemented yet */
		if (err == -ENOENT)
			return -ESRCH; /* vma not found */
		return err;
	}

	if (env_verbosity >= 1) {
		printf("VMA FOUND (addr %08lx): %08lx-%08lx %c%c%c%c %08lx %02x:%02x %ld %s (build ID: %s, %d bytes)\n",
		       (long)addr, (long)q.vma_start, (long)q.vma_end,
		       (q.vma_flags & PROCMAP_QUERY_VMA_READABLE) ? 'r' : '-',
		       (q.vma_flags & PROCMAP_QUERY_VMA_WRITABLE) ? 'w' : '-',
		       (q.vma_flags & PROCMAP_QUERY_VMA_EXECUTABLE) ? 'x' : '-',
		       (q.vma_flags & PROCMAP_QUERY_VMA_SHARED) ? 's' : 'p',
		       (long)q.vma_offset, q.dev_major, q.dev_minor, (long)q.inode,
		       q.vma_name_size ? path_buf : "",
		       q.build_id_size ? "YES" : "NO",
		       q.build_id_size);
	}

	*start = q.vma_start;
	*offset = q.vma_offset;
	*flags = q.vma_flags;
	return 0;
}
#else
# ifndef PROCMAP_QUERY_VMA_EXECUTABLE
#  define PROCMAP_QUERY_VMA_EXECUTABLE 0x04
# endif

static int procmap_query(int fd, const void *addr, __u32 query_flags, size_t *start, size_t *offset, int *flags)
{
	return -EOPNOTSUPP;
}
#endif

ssize_t get_uprobe_offset(const void *addr)
{
	size_t start, base, end;
	FILE *f;
	char buf[256];
	int err, flags;

	f = fopen("/proc/self/maps", "r");
	if (!f)
		return -errno;

	/* requested executable VMA only */
	err = procmap_query(fileno(f), addr, PROCMAP_QUERY_VMA_EXECUTABLE, &start, &base, &flags);
	if (err == -EOPNOTSUPP) {
		bool found = false;

		while (fscanf(f, "%zx-%zx %s %zx %*[^\n]\n", &start, &end, buf, &base) == 4) {
			if (buf[2] == 'x' && (uintptr_t)addr >= start && (uintptr_t)addr < end) {
				found = true;
				break;
			}
		}
		if (!found) {
			fclose(f);
			return -ESRCH;
		}
	} else if (err) {
		fclose(f);
		return err;
	}
	fclose(f);

#if defined(__powerpc64__) && defined(_CALL_ELF) && _CALL_ELF == 2

#define OP_RT_RA_MASK   0xffff0000UL
#define LIS_R2          0x3c400000UL
#define ADDIS_R2_R12    0x3c4c0000UL
#define ADDI_R2_R2      0x38420000UL

	/*
	 * A PPC64 ABIv2 function may have a local and a global entry
	 * point. We need to use the local entry point when patching
	 * functions, so identify and step over the global entry point
	 * sequence.
	 *
	 * The global entry point sequence is always of the form:
	 *
	 * addis r2,r12,XXXX
	 * addi  r2,r2,XXXX
	 *
	 * A linker optimisation may convert the addis to lis:
	 *
	 * lis   r2,XXXX
	 * addi  r2,r2,XXXX
	 */
	{
		const __u32 *insn = (const __u32 *)(uintptr_t)addr;

		if ((((*insn & OP_RT_RA_MASK) == ADDIS_R2_R12) ||
		     ((*insn & OP_RT_RA_MASK) == LIS_R2)) &&
		    ((*(insn + 1) & OP_RT_RA_MASK) == ADDI_R2_R2))
			return (uintptr_t)(insn + 2) - start + base;
	}
#endif
	return (uintptr_t)addr - start + base;
}

ssize_t get_rel_offset(uintptr_t addr)
{
	size_t start, end, offset;
	char buf[256];
	FILE *f;
	int err, flags;

	f = fopen("/proc/self/maps", "r");
	if (!f)
		return -errno;

	err = procmap_query(fileno(f), (const void *)addr, 0, &start, &offset, &flags);
	if (err == 0) {
		fclose(f);
		return (size_t)addr - start + offset;
	} else if (err != -EOPNOTSUPP) {
		fclose(f);
		return err;
	} else if (err) {
		while (fscanf(f, "%zx-%zx %s %zx %*[^\n]\n", &start, &end, buf, &offset) == 4) {
			if (addr >= start && addr < end) {
				fclose(f);
				return (size_t)addr - start + offset;
			}
		}
	}

	fclose(f);
	return -EINVAL;
}

static int
parse_build_id_buf(const void *note_start, Elf32_Word note_size, char *build_id)
{
	Elf32_Word note_offs = 0;

	while (note_offs + sizeof(Elf32_Nhdr) < note_size) {
		Elf32_Nhdr *nhdr = (Elf32_Nhdr *)(note_start + note_offs);

		if (nhdr->n_type == 3 && nhdr->n_namesz == sizeof("GNU") &&
		    !strcmp((char *)(nhdr + 1), "GNU") && nhdr->n_descsz > 0 &&
		    nhdr->n_descsz <= BPF_BUILD_ID_SIZE) {
			memcpy(build_id, note_start + note_offs +
			       ALIGN(sizeof("GNU"), 4) + sizeof(Elf32_Nhdr), nhdr->n_descsz);
			memset(build_id + nhdr->n_descsz, 0, BPF_BUILD_ID_SIZE - nhdr->n_descsz);
			return (int) nhdr->n_descsz;
		}

		note_offs = note_offs + sizeof(Elf32_Nhdr) +
			   ALIGN(nhdr->n_namesz, 4) + ALIGN(nhdr->n_descsz, 4);
	}

	return -ENOENT;
}

/* Reads binary from *path* file and returns it in the *build_id* buffer
 * with *size* which is expected to be at least BPF_BUILD_ID_SIZE bytes.
 * Returns size of build id on success. On error the error value is
 * returned.
 */
int read_build_id(const char *path, char *build_id, size_t size)
{
	int fd, err = -EINVAL;
	Elf *elf = NULL;
	GElf_Ehdr ehdr;
	size_t max, i;

	if (size < BPF_BUILD_ID_SIZE)
		return -EINVAL;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;

	(void)elf_version(EV_CURRENT);

	elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);
	if (!elf)
		goto out;
	if (elf_kind(elf) != ELF_K_ELF)
		goto out;
	if (!gelf_getehdr(elf, &ehdr))
		goto out;

	for (i = 0; i < ehdr.e_phnum; i++) {
		GElf_Phdr mem, *phdr;
		char *data;

		phdr = gelf_getphdr(elf, i, &mem);
		if (!phdr)
			goto out;
		if (phdr->p_type != PT_NOTE)
			continue;
		data = elf_rawfile(elf, &max);
		if (!data)
			goto out;
		if (phdr->p_offset + phdr->p_memsz > max)
			goto out;
		err = parse_build_id_buf(data + phdr->p_offset, phdr->p_memsz, build_id);
		if (err > 0)
			break;
	}

out:
	if (elf)
		elf_end(elf);
	close(fd);
	return err;
}

int read_trace_pipe_iter(void (*cb)(const char *str, void *data), void *data, int iter)
{
	size_t buflen, n;
	char *buf = NULL;
	FILE *fp = NULL;

	if (access(TRACEFS_PIPE, F_OK) == 0)
		fp = fopen(TRACEFS_PIPE, "r");
	else
		fp = fopen(DEBUGFS_PIPE, "r");
	if (!fp)
		return -1;

	 /* We do not want to wait forever when iter is specified. */
	if (iter)
		fcntl(fileno(fp), F_SETFL, O_NONBLOCK);

	while ((n = getline(&buf, &buflen, fp) >= 0) || errno == EAGAIN) {
		if (n > 0)
			cb(buf, data);
		if (iter && !(--iter))
			break;
	}

	free(buf);
	if (fp)
		fclose(fp);
	return 0;
}

static void trace_pipe_cb(const char *str, void *data)
{
	printf("%s", str);
}

void read_trace_pipe(void)
{
	read_trace_pipe_iter(trace_pipe_cb, NULL, 0);
}

static const char *tracefs_mountpoint(void)
{
	return access(TRACEFS_PIPE, F_OK) == 0 ? TRACEFS : DEBUGFS;
}

static int tracefs_path(char *buf, size_t size, const char *file)
{
	int ret = snprintf(buf, size, "%s/%s", tracefs_mountpoint(), file);

	return ret < 0 ? ret : 0;
}

static int tracefs_read(int fd, char **content)
{
	size_t len = 0;
	char tmp[CHUNK_SIZE];
	char *buf = NULL;
	ssize_t n;
	int ret;

	ret = lseek(fd, 0, SEEK_SET);
	if (ret < 0)
		return ret;

	do {
		n = read(fd, tmp, CHUNK_SIZE);
		if (n < 0) {
			if (buf)
				free(buf);
			return n;
		}
		if (!n)
			break;
		buf = realloc(buf, len + n + 1);
		memcpy(buf + len, tmp, n);
		len += n;
	} while (1);

	/* No data read at all, file was empty */
	if (!buf) {
		buf = malloc(1);
		if (!buf)
			return -ENOMEM;
	}
	buf[len] = '\0';
	*content = buf;
	return 0;
}

static int tracefs_write(int fd, const char *str)
{
	ssize_t ret;

	ret = lseek(fd, 0, SEEK_SET);
	if (ret < 0)
		return ret;

	ret = write(fd, str, strlen(str));
	if (ret < 0)
		return ret;
	return 0;
}

static int tracefs_write_file(const char *path, const char *str)
{
	int fd, err;

	fd = open(path, O_CLOEXEC | O_WRONLY | (*str ? 0 : O_TRUNC));
	if (fd < 0)
		return fd;

	err = tracefs_write(fd, str);
	close(fd);
	return err;
}

enum tracefs_ctl_kind {
	TRACEFS_CTL_FILTER,
	TRACEFS_CTL_VALUE,
};

struct tracefs_ctl_entry {
	char path[PATH_MAX];
	char *old;
	enum tracefs_ctl_kind kind;
};

struct tracefs_ctl {
	struct tracefs_ctl_entry *entries;
	size_t cnt;
};

struct tracefs_ctl *tracefs_ctl_init(void)
{
	return calloc(1, sizeof(struct tracefs_ctl));
}

static int tracefs_ctl_update(struct tracefs_ctl *ctl, const char *file,
			      const char *str, enum tracefs_ctl_kind kind)
{
	struct tracefs_ctl_entry *entry, *tmp;
	char path[PATH_MAX];
	char *old = NULL;
	bool recorded = false;
	size_t i;
	int fd, err;

	if (!ctl)
		return -EINVAL;

	err = tracefs_path(path, sizeof(path), file);
	if (err)
		return err;

	for (i = 0; i < ctl->cnt; i++) {
		if (strcmp(ctl->entries[i].path, path))
			continue;
		if (ctl->entries[i].kind != kind)
			return -EINVAL;
		/* Already altered, keep the value read on the first write. */
		return tracefs_write_file(ctl->entries[i].path, str);
	}

	fd = open(path, O_CLOEXEC | O_RDWR);
	if (fd < 0)
		return fd;

	err = tracefs_read(fd, &old);
	if (!err) {
		tmp = realloc(ctl->entries, (ctl->cnt + 1) * sizeof(*tmp));
		if (!tmp) {
			free(old);
			close(fd);
			return -ENOMEM;
		}
		ctl->entries = tmp;
		entry = &ctl->entries[ctl->cnt];
		strcpy(entry->path, path);
		entry->old = old;
		entry->kind = kind;
		recorded = true;
	}

	err = tracefs_write(fd, str);
	close(fd);
	if (err) {
		free(old);
		return err;
	}

	if (recorded)
		ctl->cnt++;
	return 0;
}

int tracefs_ctl_filter_write(struct tracefs_ctl *ctl, const char *file,
			     const char *pattern)
{
	return tracefs_ctl_update(ctl, file, pattern, TRACEFS_CTL_FILTER);
}

int tracefs_ctl_set(struct tracefs_ctl *ctl, const char *file, const char *value)
{
	return tracefs_ctl_update(ctl, file, value, TRACEFS_CTL_VALUE);
}

static const char *tracefs_next_line(const char *content, char *buf, size_t size,
				     int *err)
{
	const char *end;
	size_t len;

	*err = 0;
	while (*content) {
		end = strchrnul(content, '\n');
		len = end - content;
		content = *end ? end + 1 : end;

		if (!len || end[-len] == '#')
			continue;

		if (len + 2 > size) {
			*err = -ENAMETOOLONG;
			return NULL;
		}
		memcpy(buf, end - len, len);
		buf[len++] = '\n';
		buf[len] = '\0';
		return content;
	}

	return NULL;
}

static int tracefs_restore_file(const struct tracefs_ctl_entry *entry)
{
	char buf[CHUNK_SIZE];
	const char *content = entry->old;
	int err = 0;

	if (!content)
		return 0;

	if (entry->kind == TRACEFS_CTL_FILTER) {
		err = tracefs_write_file(entry->path, "");
		if (err)
			return err;
	}

	while ((content = tracefs_next_line(content, buf, sizeof(buf), &err))) {
		err = tracefs_write_file(entry->path, buf);
		if (err)
			return err;
	}

	return err;
}

void tracefs_ctl_restore(struct tracefs_ctl *ctl)
{
	size_t i;
	int err;

	if (!ctl)
		return;

	for (i = ctl->cnt; i > 0; i--) {
		struct tracefs_ctl_entry *entry = &ctl->entries[i - 1];

		err = tracefs_restore_file(entry);
		if (err)
			fprintf(stderr, "Failed to restore %s: %s\n",
				entry->path, strerror(-err));
		free(entry->old);
	}
	free(ctl->entries);
	free(ctl);
}

static size_t symbol_hash(long key, void *ctx __maybe_unused)
{
	return str_hash((const char *) key);
}

static bool symbol_equal(long key1, long key2, void *ctx __maybe_unused)
{
	return strcmp((const char *) key1, (const char *) key2) == 0;
}

static bool is_invalid_entry(char *buf, bool kernel)
{
	if (kernel && strchr(buf, '['))
		return true;
	if (!kernel && !strchr(buf, '['))
		return true;
	return false;
}

static const char * const trace_blacklist[] = {
	"migrate_disable",
	"migrate_enable",
	"rcu_read_unlock_strict",
	"preempt_count_add",
	"preempt_count_sub",
	"__rcu_read_lock",
	"__rcu_read_unlock",
	"bpf_get_numa_node_id",
	"___migrate_enable",
};

bool is_unsafe_function(const char *name)
{
	int i;

	/*
	 * We attach to almost all kernel functions and some of them
	 * will cause 'suspicious RCU usage' when fprobe is attached
	 * to them. Filter out the current culprits - arch_cpu_idle
	 * default_idle and rcu_* functions.
	 */
	if (!strcmp(name, "arch_cpu_idle"))
		return true;
	if (!strcmp(name, "default_idle"))
		return true;
	if (!strncmp(name, "rcu_", 4))
		return true;
	if (!strcmp(name, "bpf_dispatcher_xdp_func"))
		return true;
	if (!strncmp(name, "__ftrace_invalid_address__",
		     sizeof("__ftrace_invalid_address__") - 1))
		return true;

	for (i = 0; i < ARRAY_SIZE(trace_blacklist); i++) {
		if (!strcmp(name, trace_blacklist[i]))
			return true;
	}

	return false;
}

/* Do comparison by ignoring '.llvm.<hash>' suffixes. */
static int compare_name(const char *name1, const char *name2)
{
	const char *res1, *res2;
	int len1, len2;

	res1 = strstr(name1, ".llvm.");
	res2 = strstr(name2, ".llvm.");
	len1 = res1 ? res1 - name1 : strlen(name1);
	len2 = res2 ? res2 - name2 : strlen(name2);

	if (len1 == len2)
		return strncmp(name1, name2, len1);
	if (len1 < len2)
		return strncmp(name1, name2, len1) <= 0 ? -1 : 1;
	return strncmp(name1, name2, len2) >= 0 ? 1 : -1;
}

static int load_kallsyms_compare(const void *p1, const void *p2)
{
	return compare_name(((const struct ksym *)p1)->name, ((const struct ksym *)p2)->name);
}

static int search_kallsyms_compare(const void *p1, const struct ksym *p2)
{
	return compare_name(p1, p2->name);
}

int bpf_get_ksyms(struct ksyms **ksymsp, bool kernel)
{
	size_t cap = 0, cnt = 0;
	char *name = NULL, *ksym_name, **syms = NULL;
	struct hashmap *map;
	struct ksyms *ksyms;
	struct ksym *ks;
	char buf[256];
	FILE *f;
	int err = 0;

	ksyms = load_kallsyms_custom_local(load_kallsyms_compare);
	if (!ksyms)
		return -EINVAL;

	/*
	 * The available_filter_functions contains many duplicates,
	 * but other than that all symbols are usable to trace.
	 * Filtering out duplicates by using hashmap__add, which won't
	 * add existing entry.
	 */

	if (access("/sys/kernel/tracing/trace", F_OK) == 0)
		f = fopen("/sys/kernel/tracing/available_filter_functions", "r");
	else
		f = fopen("/sys/kernel/debug/tracing/available_filter_functions", "r");

	if (!f) {
		free_kallsyms_local(ksyms);
		return -EINVAL;
	}

	map = hashmap__new(symbol_hash, symbol_equal, NULL);
	if (IS_ERR(map)) {
		err = libbpf_get_error(map);
		goto error;
	}

	while (fgets(buf, sizeof(buf), f)) {
		if (is_invalid_entry(buf, kernel))
			continue;

		free(name);
		if (sscanf(buf, "%ms$*[^\n]\n", &name) != 1)
			continue;
		if (is_unsafe_function(name))
			continue;

		ks = search_kallsyms_custom_local(ksyms, name, search_kallsyms_compare);
		if (!ks) {
			err = -EINVAL;
			goto error;
		}

		ksym_name = ks->name;
		err = hashmap__add(map, ksym_name, 0);
		if (err == -EEXIST) {
			err = 0;
			continue;
		}
		if (err)
			goto error;

		err = libbpf_ensure_mem((void **) &syms, &cap,
					sizeof(*syms), cnt + 1);
		if (err)
			goto error;

		syms[cnt++] = ksym_name;
	}

	ksyms->filtered_syms = syms;
	ksyms->filtered_cnt = cnt;
	*ksymsp = ksyms;

error:
	free(name);
	fclose(f);
	hashmap__free(map);
	if (err) {
		free(syms);
		free_kallsyms_local(ksyms);
	}
	return err;
}

int bpf_get_addrs(unsigned long **addrsp, size_t *cntp, bool kernel)
{
	unsigned long *addr, *addrs, *tmp_addrs;
	int err = 0, max_cnt, inc_cnt;
	char *name = NULL;
	size_t cnt = 0;
	char buf[256];
	FILE *f;

	if (access("/sys/kernel/tracing/trace", F_OK) == 0)
		f = fopen("/sys/kernel/tracing/available_filter_functions_addrs", "r");
	else
		f = fopen("/sys/kernel/debug/tracing/available_filter_functions_addrs", "r");

	if (!f)
		return -ENOENT;

	/* In my local setup, the number of entries is 50k+ so Let us initially
	 * allocate space to hold 64k entries. If 64k is not enough, incrementally
	 * increase 1k each time.
	 */
	max_cnt = 65536;
	inc_cnt = 1024;
	addrs = malloc(max_cnt * sizeof(long));
	if (addrs == NULL) {
		err = -ENOMEM;
		goto error;
	}

	while (fgets(buf, sizeof(buf), f)) {
		if (is_invalid_entry(buf, kernel))
			continue;

		free(name);
		if (sscanf(buf, "%p %ms$*[^\n]\n", &addr, &name) != 2)
			continue;
		if (is_unsafe_function(name))
			continue;

		if (cnt == max_cnt) {
			max_cnt += inc_cnt;
			tmp_addrs = realloc(addrs, max_cnt * sizeof(long));
			if (!tmp_addrs) {
				err = -ENOMEM;
				goto error;
			}
			addrs = tmp_addrs;
		}

		addrs[cnt++] = (unsigned long)addr;
	}

	*addrsp = addrs;
	*cntp = cnt;

error:
	free(name);
	fclose(f);
	if (err)
		free(addrs);
	return err;
}
