// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <argp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

static bool verbose;
static bool quiet;
static bool use_ioctl;
static bool request_build_id;
static char *addrs_path;
static int pid;
static int bench_runs;

const char *argp_program_version = "procfs_query 0.0";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";

static inline uint64_t get_time_ns(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);

	return (uint64_t)t.tv_sec * 1000000000 + t.tv_nsec;
}

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose mode" },
	{ "quiet", 'q', NULL, 0, "Quiet mode (no output)" },
	{ "pid", 'p', "PID", 0, "PID of the process" },
	{ "addrs-path", 'f', "PATH", 0, "File with addresses to resolve" },
	{ "benchmark", 'B', "RUNS", 0, "Benchmark mode" },
	{ "query", 'Q', NULL, 0, "Use ioctl()-based point query API (by default text parsing is done)" },
	{ "build-id", 'b', NULL, 0, "Fetch build ID, if available (only for ioctl mode)" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		verbose = true;
		break;
	case 'q':
		quiet = true;
		break;
	case 'Q':
		use_ioctl = true;
		break;
	case 'b':
		request_build_id = true;
		break;
	case 'p':
		pid = strtol(arg, NULL, 10);
		break;
	case 'f':
		addrs_path = strdup(arg);
		break;
	case 'B':
		bench_runs = strtol(arg, NULL, 10);
		if (bench_runs <= 0) {
			fprintf(stderr, "Invalid benchmark run count: %s\n", arg);
			return -EINVAL;
		}
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
};

struct addr {
	unsigned long long addr;
	int idx;
};

static struct addr *addrs;
static size_t addr_cnt, addr_cap;

struct resolved_addr {
	unsigned long long file_off;
	const char *vma_name;
	int build_id_sz;
	char build_id[20];
};

static struct resolved_addr *resolved;

static int resolve_addrs_ioctl(void)
{
	char buf[32], build_id_buf[20], vma_name[PATH_MAX];
	struct procmap_query q;
	int fd, err, i;
	struct addr *a = &addrs[0];
	struct resolved_addr *r;

	snprintf(buf, sizeof(buf), "/proc/%d/maps", pid);
	fd = open(buf, O_RDONLY);
	if (fd < 0) {
		err = -errno;
		fprintf(stderr, "Failed to open process map file (%s): %d\n", buf, err);
		return err;
	}

	memset(&q, 0, sizeof(q));
	q.size = sizeof(q);
	q.query_flags = PROCMAP_QUERY_COVERING_OR_NEXT_VMA;
	q.vma_name_addr = (__u64)vma_name;
	if (request_build_id)
		q.build_id_addr = (__u64)build_id_buf;

	for (i = 0; i < addr_cnt; ) {
		char *name = NULL;

		q.query_addr = (__u64)a->addr;
		q.vma_name_size = sizeof(vma_name);
		if (request_build_id)
			q.build_id_size = sizeof(build_id_buf);

		err = ioctl(fd, PROCMAP_QUERY, &q);
		if (err < 0 && errno == ENOTTY) {
			close(fd);
			fprintf(stderr, "PROCMAP_QUERY ioctl() command is not supported on this kernel!\n");
			return -EOPNOTSUPP; /* ioctl() not implemented yet */
		}
		if (err < 0 && errno == ENOENT) {
			fprintf(stderr, "ENOENT addr %lx\n", (long)q.query_addr);
			i++;
			a++;
			continue; /* unresolved address */
		}
		if (err < 0) {
			err = -errno;
			close(fd);
			fprintf(stderr, "PROCMAP_QUERY ioctl() returned error: %d\n", err);
			return err;
		}

		if (verbose) {
			printf("VMA FOUND (addr %08lx): %08lx-%08lx %c%c%c%c %08lx %02x:%02x %ld %s (build ID: %s, %d bytes)\n",
			       (long)q.query_addr, (long)q.vma_start, (long)q.vma_end,
			       (q.vma_flags & PROCMAP_QUERY_VMA_READABLE) ? 'r' : '-',
			       (q.vma_flags & PROCMAP_QUERY_VMA_WRITABLE) ? 'w' : '-',
			       (q.vma_flags & PROCMAP_QUERY_VMA_EXECUTABLE) ? 'x' : '-',
			       (q.vma_flags & PROCMAP_QUERY_VMA_SHARED) ? 's' : 'p',
			       (long)q.vma_offset, q.dev_major, q.dev_minor, (long)q.inode,
			       q.vma_name_size ? vma_name : "",
			       q.build_id_size ? "YES" : "NO",
			       q.build_id_size);
		}

		/* skip addrs falling before current VMA */
		for (; i < addr_cnt && a->addr < q.vma_start; i++, a++) {
		}
		/* process addrs covered by current VMA */
		for (; i < addr_cnt && a->addr < q.vma_end; i++, a++) {
			r = &resolved[a->idx];
			r->file_off = a->addr - q.vma_start + q.vma_offset;

			/* reuse name, if it was already strdup()'ed */
			if (q.vma_name_size)
				name = name ?: strdup(vma_name);
			r->vma_name = name;

			if (q.build_id_size) {
				r->build_id_sz = q.build_id_size;
				memcpy(r->build_id, build_id_buf, q.build_id_size);
			}
		}
	}

	close(fd);
	return 0;
}

static int resolve_addrs_parse(void)
{
	size_t vma_start, vma_end, vma_offset, ino;
	uint32_t dev_major, dev_minor;
	char perms[4], buf[32], vma_name[PATH_MAX], fbuf[4096];
	FILE *f;
	int err, idx = 0;
	struct addr *a = &addrs[idx];
	struct resolved_addr *r;

	snprintf(buf, sizeof(buf), "/proc/%d/maps", pid);
	f = fopen(buf, "r");
	if (!f) {
		err = -errno;
		fprintf(stderr, "Failed to open process map file (%s): %d\n", buf, err);
		return err;
	}

	err = setvbuf(f, fbuf, _IOFBF, sizeof(fbuf));
	if (err) {
		err = -errno;
		fprintf(stderr, "Failed to set custom file buffer size: %d\n", err);
		return err;
	}

	while ((err = fscanf(f, "%zx-%zx %c%c%c%c %zx %x:%x %zu %[^\n]\n",
			     &vma_start, &vma_end,
			     &perms[0], &perms[1], &perms[2], &perms[3],
			     &vma_offset, &dev_major, &dev_minor, &ino, vma_name)) >= 10) {
		const char *name = NULL;

		/* skip addrs before current vma, they stay unresolved */
		for (; idx < addr_cnt && a->addr < vma_start; idx++, a++) {
		}

		/* resolve all addrs within current vma now */
		for (; idx < addr_cnt && a->addr < vma_end; idx++, a++) {
			r = &resolved[a->idx];
			r->file_off = a->addr - vma_start + vma_offset;

			/* reuse name, if it was already strdup()'ed */
			if (err > 10)
				name = name ?: strdup(vma_name);
			else
				name = NULL;
			r->vma_name = name;
		}

		/* ran out of addrs to resolve, stop early */
		if (idx >= addr_cnt)
			break;
	}

	fclose(f);
	return 0;
}

static int cmp_by_addr(const void *a, const void *b)
{
	const struct addr *x = a, *y = b;

	if (x->addr != y->addr)
		return x->addr < y->addr ? -1 : 1;
	return x->idx < y->idx ? -1 : 1;
}

static int cmp_by_idx(const void *a, const void *b)
{
	const struct addr *x = a, *y = b;

	return x->idx < y->idx ? -1 : 1;
}

int main(int argc, char **argv)
{
	FILE* f;
	int err, i;
	unsigned long long addr;
	uint64_t start_ns;
	double total_ns;

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (pid <= 0 || !addrs_path) {
		fprintf(stderr, "Please provide PID and file with addresses to process!\n");
		exit(1);
	}

	if (verbose) {
		fprintf(stderr, "PID: %d\n", pid);
		fprintf(stderr, "PATH: %s\n", addrs_path);
	}

	f = fopen(addrs_path, "r");
	if (!f) {
		err = -errno;
		fprintf(stderr, "Failed to open '%s': %d\n", addrs_path, err);
		goto out;
	}

	while ((err = fscanf(f, "%llx\n", &addr)) == 1) {
		if (addr_cnt == addr_cap) {
			addr_cap = addr_cap == 0 ? 16 : (addr_cap * 3 / 2);
			addrs = realloc(addrs, sizeof(*addrs) * addr_cap);
			memset(addrs + addr_cnt, 0, (addr_cap - addr_cnt) * sizeof(*addrs));
		}

		addrs[addr_cnt].addr = addr;
		addrs[addr_cnt].idx = addr_cnt;

		addr_cnt++;
	}
	if (verbose)
		fprintf(stderr, "READ %zu addrs!\n", addr_cnt);
	if (!feof(f)) {
		fprintf(stderr, "Failure parsing full list of addresses at '%s'!\n", addrs_path);
		err = -EINVAL;
		fclose(f);
		goto out;
	}
	fclose(f);
	if (addr_cnt == 0) {
		fprintf(stderr, "No addresses provided, bailing out!\n");
		err = -ENOENT;
		goto out;
	}

	resolved = calloc(addr_cnt, sizeof(*resolved));

	qsort(addrs, addr_cnt, sizeof(*addrs), cmp_by_addr);
	if (verbose) {
		fprintf(stderr, "SORTED ADDRS (%zu):\n", addr_cnt);
		for (i = 0; i < addr_cnt; i++) {
			fprintf(stderr, "ADDR #%d: %#llx\n", addrs[i].idx, addrs[i].addr);
		}
	}

	start_ns = get_time_ns();
	for (i = bench_runs ?: 1; i > 0; i--) {
		if (use_ioctl) {
			err = resolve_addrs_ioctl();
		} else {
			err = resolve_addrs_parse();
		}
		if (err) {
			fprintf(stderr, "Failed to resolve addrs: %d!\n", err);
			goto out;
		}
	}
	total_ns = get_time_ns() - start_ns;

	if (bench_runs) {
		fprintf(stderr, "BENCHMARK MODE. RUNS: %d TOTAL TIME (ms): %.3lf TIME/RUN (ms): %.3lf TIME/ADDR (us): %.3lf\n",
			bench_runs, total_ns / 1000000.0, total_ns / bench_runs / 1000000.0,
			total_ns / bench_runs / addr_cnt / 1000.0);
	}

	/* sort them back into the original order */
	qsort(addrs, addr_cnt, sizeof(*addrs), cmp_by_idx);

	if (!quiet) {
		printf("RESOLVED ADDRS (%zu):\n", addr_cnt);
		for (i = 0; i < addr_cnt; i++) {
			const struct addr *a = &addrs[i];
			const struct resolved_addr *r = &resolved[a->idx];

			if (r->file_off) {
				printf("RESOLVED   #%d: %#llx -> OFF %#llx",
					a->idx, a->addr, r->file_off);
				if (r->vma_name)
					printf(" NAME %s", r->vma_name);
				if (r->build_id_sz) {
					char build_id_str[41];
					int j;

					for (j = 0; j < r->build_id_sz; j++)
						sprintf(&build_id_str[j * 2], "%02hhx", r->build_id[j]);
					printf(" BUILDID %s", build_id_str);
				}
				printf("\n");
			} else {
				printf("UNRESOLVED #%d: %#llx\n", a->idx, a->addr);
			}
		}
	}
out:
	free(addrs);
	free(addrs_path);
	free(resolved);

	return err < 0 ? -err : 0;
}
