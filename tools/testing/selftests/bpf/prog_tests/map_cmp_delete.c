// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2026 NAVER Corp.
 *
 * Author: Gyutae Bae <gyutae.bae@navercorp.com>
 */

#include <test_progs.h>
#include <sys/syscall.h>

struct val {
	__u64 revision;	/* synchronization field we compare on */
	__u64 payload;
};

/* libbpf has no wrapper that passes the compare-and-delete fields, so
 * issue bpf() directly. 'flags' is a parameter so tests can also
 * exercise the no-BPF_F_COMPARE case.
 */
static int cmp_delete_flags(int fd, const void *key, const void *compare,
			    __u32 off, __u32 size, __u64 flags)
{
	union bpf_attr attr;
	int ret;

	memset(&attr, 0, sizeof(attr));
	attr.map_fd = fd;
	attr.key = (__u64)(unsigned long)key;
	attr.flags = flags;
	attr.compare = (__u64)(unsigned long)compare;
	attr.compare_offset = off;
	attr.compare_size = size;
	ret = syscall(__NR_bpf, BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
	return ret < 0 ? -errno : ret;
}

static int cmp_delete(int fd, const void *key, const void *compare,
		      __u32 off, __u32 size)
{
	return cmp_delete_flags(fd, key, compare, off, size, BPF_F_COMPARE);
}

static int hash_map(void)
{
	return bpf_map_create(BPF_MAP_TYPE_HASH, "cmp_hash",
			      sizeof(__u32), sizeof(struct val), 64, NULL);
}

static void test_contract(void)
{
	const __u32 off = offsetof(struct val, revision);
	const __u32 sz = sizeof(((struct val *)0)->revision);
	struct val v = { .revision = 10, .payload = 0xabc };
	struct val snap = v;
	__u32 k = 1;
	int fd = hash_map();

	if (!ASSERT_GE(fd, 0, "map_create"))
		return;
	ASSERT_OK(bpf_map_update_elem(fd, &k, &v, BPF_ANY), "insert");

	/* mismatch -> -EBUSY, entry preserved */
	snap.revision = 9;
	ASSERT_EQ(cmp_delete(fd, &k, &snap, off, sz), -EBUSY, "mismatch_ebusy");
	ASSERT_OK(bpf_map_lookup_elem(fd, &k, &v), "still_present");

	/* compare fields set but BPF_F_COMPARE omitted -> -EINVAL, entry preserved
	 * (a dropped flag must not silently become an unconditional delete)
	 */
	ASSERT_EQ(cmp_delete_flags(fd, &k, &snap, off, sz, 0), -EINVAL,
		  "cmp_fields_no_flag_einval");
	ASSERT_OK(bpf_map_lookup_elem(fd, &k, &v), "preserved_no_flag");

	/* match -> 0, entry gone */
	snap.revision = 10;
	ASSERT_OK(cmp_delete(fd, &k, &snap, off, sz), "match_deletes");
	ASSERT_EQ(bpf_map_lookup_elem(fd, &k, &v), -ENOENT, "gone");

	/* absent -> -ENOENT */
	ASSERT_EQ(cmp_delete(fd, &k, &snap, off, sz), -ENOENT, "absent_enoent");

	/* bad window -> -EINVAL */
	ASSERT_EQ(cmp_delete(fd, &k, &snap, 0, sizeof(struct val) + 8), -EINVAL,
		  "oversize_einval");

	/* unsupported map type (no map_delete_elem_cmp op) -> -EOPNOTSUPP */
	{
		int afd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "cmp_arr",
					 sizeof(__u32), sizeof(struct val), 4, NULL);
		__u32 ak = 0;

		if (ASSERT_GE(afd, 0, "array_create")) {
			ASSERT_EQ(cmp_delete(afd, &ak, &snap, off, sz),
				  -EOPNOTSUPP, "array_eopnotsupp");
			close(afd);
		}
	}
	close(fd);
}

void test_map_cmp_delete(void)
{
	if (test__start_subtest("contract"))
		test_contract();
}
