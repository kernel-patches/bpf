// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

__u32 filter_en;
__u32 filter_pid;
__u32 total_seen;
__u32 printed_lines;

__u32 open_coded_seen;
__u32 nid_seen;
__s32 first_nid = -1;
char stack_text[2048];
__u32 stack_bytes;

__u32 memcg_seen;
__u32 memcg_charged;
__u32 memcg_online;
__u32 memcg_nodata;
__u32 memcg_notsup;
__u32 memcg_bad;
__u32 memcg_first_saved;
__u32 memcg_first_flags;	/* bit0 is_online, bit1 is_kmem */
__u32 memcg_first_path_len;
char memcg_pathbuf[4096];
char memcg_first_path[4096];
char memcg_first_name[80];

#define MEMCG_ENODATA 61
#define MEMCG_EOPNOTSUPP 95

#define MEMCG_F_ONLINE	(1 << 0)
#define MEMCG_F_OBJCG	(1 << 1)

extern int bpf_iter_page_owner_new(struct bpf_iter_page_owner *it) __ksym;
extern struct page_owner_scan *
bpf_iter_page_owner_next(struct bpf_iter_page_owner *it) __ksym;
extern void bpf_iter_page_owner_destroy(struct bpf_iter_page_owner *it) __ksym;
extern int bpf_page_owner_stack_snprint(depot_stack_handle_t handle,
					char *buf, u32 buf_size) __ksym;
extern int bpf_page_owner_get_nid(struct page_owner_scan *scan) __ksym;
extern int bpf_page_owner_get_memcg_info(struct page_owner_scan *scan,
					 struct memcg_info *info,
					 char *buf, u32 size) __ksym;

static __u32 copy_str(char *dst, const char *src, const __u32 max)
{
	__u32 i = 0;

	while (i + 1 < max && src[i]) {
		dst[i] = src[i];
		i++;
	}
	dst[i] = '\0';
	return i;
}

/*
 * Exercise bpf_page_owner_get_memcg_info() until 32 pages charged to an
 * ONLINE memcg have been seen, checking its per-return contract:
 *  - 0:          buf holds an absolute cgroup path;
 *  - -ENODATA:   buf was NUL-terminated;
 *  - -EOPNOTSUPP: counted (CONFIG_MEMCG is off);
 *
 * The first online charged sample is saved for userspace to print and
 * cross-check (name vs basename of path).
 */
static void check_memcg(struct page_owner_scan *scan)
{
	static struct memcg_info info;
	int err;

	err = bpf_page_owner_get_memcg_info(scan, &info, memcg_pathbuf,
					    sizeof(memcg_pathbuf));
	memcg_seen++;

	if (err == 0) {
		memcg_charged++;

		if (memcg_pathbuf[0] != '/') {
			memcg_bad++;
			return;
		}

		if (!info.is_online)
			return;
		memcg_online++;

		/* keep the first online sample for userspace */
		if (!memcg_first_saved) {
			memcg_first_path_len = copy_str(memcg_first_path,
							memcg_pathbuf,
							sizeof(memcg_first_path));
			copy_str(memcg_first_name, info.name,
				 sizeof(memcg_first_name));
			memcg_first_flags = MEMCG_F_ONLINE |
					    (info.is_kmem ? MEMCG_F_OBJCG : 0);
			memcg_first_saved = 1;
		}
	} else if (err == -MEMCG_ENODATA) {
		memcg_nodata++;
		if (memcg_pathbuf[0] != '\0')
			memcg_bad++;
	} else if (err == -MEMCG_EOPNOTSUPP) {
		memcg_notsup++;
		if (memcg_pathbuf[0] != '\0')
			memcg_bad++;
	} else {
		memcg_bad++;
	}
}

SEC("syscall")
int scan_open_coded(const void *ctx)
{
	struct bpf_iter_page_owner it;
	struct page_owner_scan *scan;

	bpf_iter_page_owner_new(&it);

	while ((scan = bpf_iter_page_owner_next(&it))) {
		open_coded_seen++;
		if (bpf_page_owner_get_nid(scan) >= 0)
			nid_seen++;
		if (memcg_online < 32)
			check_memcg(scan);
		/* grab the stack of the 100th page for userspace to check */
		if (open_coded_seen == 100) {
			first_nid = bpf_page_owner_get_nid(scan);
			if (scan->po_snap.handle)
				stack_bytes = bpf_page_owner_stack_snprint(
					scan->po_snap.handle,
					stack_text, sizeof(stack_text));
		}
	}
	bpf_iter_page_owner_destroy(&it);
	return 0;
}

SEC("iter/page_owner")
int dump_page_owner(struct bpf_iter__page_owner *ctx)
{
	struct page_owner *po = ctx->po;

	if (!po)
		return 0;

	total_seen++;

	if (filter_en && po->pid != (pid_t)filter_pid)
		return 0;

	BPF_SEQ_PRINTF(ctx->meta->seq, "pfn %llu pid %d comm %s\n",
		       ctx->pfn, po->pid, po->comm);
	printed_lines++;
	return 0;
}
