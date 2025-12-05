// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <sys/mman.h>
#include "test_mmap.skel.h"

struct map_data {
	__u64 val[512 * 4];
};

static size_t roundup_page(size_t sz)
{
	long page_size = sysconf(_SC_PAGE_SIZE);
	return (sz + page_size - 1) / page_size * page_size;
}

void test_mmap(void)
{
	const size_t bss_sz = roundup_page(sizeof(struct test_mmap__bss));
	const size_t map_sz = roundup_page(sizeof(struct map_data));
	const int zero = 0, one = 1, two = 2, far = 1500;
	const long page_size = sysconf(_SC_PAGE_SIZE);
	int err, i, data_map_fd, data_map_id, tmp_fd, rdmap_fd;
	struct bpf_map *data_map, *bss_map;
	void *bss_mmaped = NULL, *map_mmaped = NULL, *tmp0, *tmp1, *tmp2;
	struct test_mmap__bss *bss_data;
	struct bpf_map_info map_info;
	__u32 map_info_sz = sizeof(map_info);
	struct map_data *map_data;
	struct test_mmap *skel;
	__u64 val = 0;

	skel = test_mmap__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	err = bpf_map__set_max_entries(skel->maps.rdonly_map, page_size);
	if (!ASSERT_OK(err, "bpf_map__set_max_entries"))
		goto cleanup;

	/* at least 4 pages of data */
	err = bpf_map__set_max_entries(skel->maps.data_map,
				       4 * (page_size / sizeof(u64)));
	if (!ASSERT_OK(err, "bpf_map__set_max_entries"))
		goto cleanup;

	err = test_mmap__load(skel);
	if (!ASSERT_OK(err, "skel_load"))
		goto cleanup;

	bss_map = skel->maps.bss;
	data_map = skel->maps.data_map;
	data_map_fd = bpf_map__fd(data_map);

	rdmap_fd = bpf_map__fd(skel->maps.rdonly_map);
	tmp1 = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, rdmap_fd, 0);
	if (!ASSERT_EQ(tmp1, MAP_FAILED, "rdonly_write_mmap")) {
		munmap(tmp1, page_size);
		goto cleanup;
	}
	/* now double-check if it's mmap()'able at all */
	tmp1 = mmap(NULL, page_size, PROT_READ, MAP_SHARED, rdmap_fd, 0);
	if (tmp1 == MAP_FAILED) {
		PERROR("rdonly_read_mmap");
		goto cleanup;
	}

	/* get map's ID */
	memset(&map_info, 0, map_info_sz);
	err = bpf_map_get_info_by_fd(data_map_fd, &map_info, &map_info_sz);
	if (!ASSERT_OK(err, "map_get_info"))
		goto cleanup;
	data_map_id = map_info.id;

	/* mmap BSS map */
	bss_mmaped = mmap(NULL, bss_sz, PROT_READ | PROT_WRITE, MAP_SHARED,
			  bpf_map__fd(bss_map), 0);
	if (bss_mmaped == MAP_FAILED) {
		PERROR("bss_mmap");
		bss_mmaped = NULL;
		goto cleanup;
	}
	/* map as R/W first */
	map_mmaped = mmap(NULL, map_sz, PROT_READ | PROT_WRITE, MAP_SHARED,
			  data_map_fd, 0);
	if (map_mmaped == MAP_FAILED) {
		PERROR("data_mmap");
		map_mmaped = NULL;
		goto cleanup;
	}

	bss_data = bss_mmaped;
	map_data = map_mmaped;

	ASSERT_EQ(bss_data->in_val, 0, "bss_data->in_val");
	ASSERT_EQ(bss_data->out_val, 0, "bss_data->out_val");
	ASSERT_EQ(skel->bss->in_val, 0, "skel->bss->in_val");
	ASSERT_EQ(skel->bss->out_val, 0, "skel->bss->out_val");
	ASSERT_EQ(map_data->val[0], 0, "map_data->val[0]");
	ASSERT_EQ(map_data->val[1], 0, "map_data->val[1]");
	ASSERT_EQ(map_data->val[2], 0, "map_data->val[2]");
	ASSERT_EQ(map_data->val[far], 0, "map_data->val[far]");

	err = test_mmap__attach(skel);
	if (!ASSERT_OK(err, "attach_raw_tp"))
		goto cleanup;

	bss_data->in_val = 123;
	val = 111;
	ASSERT_OK(bpf_map_update_elem(data_map_fd, &zero, &val, 0), "map_update_elem");

	usleep(1);

	ASSERT_EQ(bss_data->in_val, 123, "bss_data->in_val");
	ASSERT_EQ(bss_data->out_val, 123, "bss_data->out_val");
	ASSERT_EQ(skel->bss->in_val, 123, "skel->bss->in_val");
	ASSERT_EQ(skel->bss->out_val, 123, "skel->bss->out_val");
	ASSERT_EQ(map_data->val[0], 111, "map_data->val[0]");
	ASSERT_EQ(map_data->val[1], 222, "map_data->val[1]");
	ASSERT_EQ(map_data->val[2], 123, "map_data->val[2]");
	ASSERT_EQ(map_data->val[far], 3 * 123, "map_data->val[far]");

	ASSERT_OK(bpf_map_lookup_elem(data_map_fd, &zero, &val), "map_lookup_elem zero");
	ASSERT_EQ(val, 111, "val after lookup zero");
	ASSERT_OK(bpf_map_lookup_elem(data_map_fd, &one, &val), "map_lookup_elem one");
	ASSERT_EQ(val, 222, "val after lookup one");
	ASSERT_OK(bpf_map_lookup_elem(data_map_fd, &two, &val), "map_lookup_elem two");
	ASSERT_EQ(val, 123, "val after lookup two");
	ASSERT_OK(bpf_map_lookup_elem(data_map_fd, &far, &val), "map_lookup_elem far");
	ASSERT_EQ(val, 3 * 123, "val after lookup far");

	/* data_map freeze should fail due to R/W mmap() */
	err = bpf_map_freeze(data_map_fd);
	if (!err || errno != EBUSY) {
		PERROR("no_freeze");
		goto cleanup;
	}

	err = mprotect(map_mmaped, map_sz, PROT_READ);
	if (!ASSERT_OK(err, "mprotect_ro"))
		goto cleanup;

	/* unmap R/W mapping */
	err = munmap(map_mmaped, map_sz);
	map_mmaped = NULL;
	if (!ASSERT_OK(err, "data_map_munmap"))
		goto cleanup;

	/* re-map as R/O now */
	map_mmaped = mmap(NULL, map_sz, PROT_READ, MAP_SHARED, data_map_fd, 0);
	if (map_mmaped == MAP_FAILED) {
		PERROR("data_mmap");
		map_mmaped = NULL;
		goto cleanup;
	}
	err = mprotect(map_mmaped, map_sz, PROT_WRITE);
	if (!ASSERT_ERR(err, "mprotect_wr"))
		goto cleanup;
	err = mprotect(map_mmaped, map_sz, PROT_EXEC);
	if (!ASSERT_ERR(err, "mprotect_ex"))
		goto cleanup;
	map_data = map_mmaped;

	/* map/unmap in a loop to test ref counting */
	for (i = 0; i < 10; i++) {
		int flags = i % 2 ? PROT_READ : PROT_WRITE;
		void *p;

		p = mmap(NULL, map_sz, flags, MAP_SHARED, data_map_fd, 0);
		if (!ASSERT_NEQ(p, MAP_FAILED, "mmap in loop"))
			goto cleanup;
		err = munmap(p, map_sz);
		if (!ASSERT_OK(err, "munmap in loop"))
			goto cleanup;
	}

	/* data_map freeze should now succeed due to no R/W mapping */
	err = bpf_map_freeze(data_map_fd);
	if (!ASSERT_OK(err, "freeze"))
		goto cleanup;

	/* mapping as R/W now should fail */
	tmp1 = mmap(NULL, map_sz, PROT_READ | PROT_WRITE, MAP_SHARED,
		    data_map_fd, 0);
	if (!ASSERT_EQ(tmp1, MAP_FAILED, "data_mmap")) {
		munmap(tmp1, map_sz);
		goto cleanup;
	}

	bss_data->in_val = 321;
	usleep(1);
	ASSERT_EQ(bss_data->in_val, 321, "bss_data->in_val");
	ASSERT_EQ(bss_data->out_val, 321, "bss_data->out_val");
	ASSERT_EQ(skel->bss->in_val, 321, "skel->bss->in_val");
	ASSERT_EQ(skel->bss->out_val, 321, "skel->bss->out_val");
	ASSERT_EQ(map_data->val[0], 111, "map_data->val[0]");
	ASSERT_EQ(map_data->val[1], 222, "map_data->val[1]");
	ASSERT_EQ(map_data->val[2], 321, "map_data->val[2]");
	ASSERT_EQ(map_data->val[far], 3 * 321, "map_data->val[far]");

	/* check some more advanced mmap() manipulations */

	tmp0 = mmap(NULL, 4 * page_size, PROT_READ, MAP_SHARED | MAP_ANONYMOUS,
			  -1, 0);
	if (tmp0 == MAP_FAILED) {
		PERROR("adv_mmap0");
		goto cleanup;
	}

	/* map all but last page: pages 1-3 mapped */
	tmp1 = mmap(tmp0, 3 * page_size, PROT_READ, MAP_SHARED | MAP_FIXED,
			  data_map_fd, 0);
	if (!ASSERT_EQ(tmp0, tmp1, "adv_mmap1")) {
		munmap(tmp0, 4 * page_size);
		goto cleanup;
	}

	/* unmap second page: pages 1, 3 mapped */
	err = munmap(tmp1 + page_size, page_size);
	if (!ASSERT_OK(err, "adv_mmap2")) {
		munmap(tmp1, 4 * page_size);
		goto cleanup;
	}

	/* map page 2 back */
	tmp2 = mmap(tmp1 + page_size, page_size, PROT_READ,
		    MAP_SHARED | MAP_FIXED, data_map_fd, 0);
	if (tmp2 == MAP_FAILED) {
		PERROR("adv_mmap3");
		munmap(tmp1, page_size);
		munmap(tmp1 + 2*page_size, 2 * page_size);
		goto cleanup;
	}
	ASSERT_EQ(tmp1 + page_size, tmp2, "adv_mmap4");

	/* re-map all 4 pages */
	tmp2 = mmap(tmp1, 4 * page_size, PROT_READ, MAP_SHARED | MAP_FIXED,
		    data_map_fd, 0);
	if (tmp2 == MAP_FAILED) {
		PERROR("adv_mmap5");
		munmap(tmp1, 4 * page_size); /* unmap page 1 */
		goto cleanup;
	}
	ASSERT_EQ(tmp1, tmp2, "adv_mmap6");

	map_data = tmp2;
	ASSERT_EQ(bss_data->in_val, 321, "bss_data->in_val");
	ASSERT_EQ(bss_data->out_val, 321, "bss_data->out_val");
	ASSERT_EQ(skel->bss->in_val, 321, "skel->bss->in_val");
	ASSERT_EQ(skel->bss->out_val, 321, "skel->bss->out_val");
	ASSERT_EQ(map_data->val[0], 111, "map_data->val[0]");
	ASSERT_EQ(map_data->val[1], 222, "map_data->val[1]");
	ASSERT_EQ(map_data->val[2], 321, "map_data->val[2]");
	ASSERT_EQ(map_data->val[far], 3 * 321, "map_data->val[far]");

	munmap(tmp2, 4 * page_size);

	/* map all 4 pages, but with pg_off=1 page, should fail */
	tmp1 = mmap(NULL, 4 * page_size, PROT_READ, MAP_SHARED | MAP_FIXED,
		    data_map_fd, page_size /* initial page shift */);
	if (!ASSERT_EQ(tmp1, MAP_FAILED, "adv_mmap7")) {
		munmap(tmp1, 4 * page_size);
		goto cleanup;
	}

	tmp1 = mmap(NULL, map_sz, PROT_READ, MAP_SHARED, data_map_fd, 0);
	if (tmp1 == MAP_FAILED) {
		PERROR("last_mmap");
		goto cleanup;
	}

	test_mmap__destroy(skel);
	skel = NULL;
	ASSERT_OK(munmap(bss_mmaped, bss_sz), "munmap bss_mmaped");
	bss_mmaped = NULL;
	ASSERT_OK(munmap(map_mmaped, map_sz), "munmap map_mmaped");
	map_mmaped = NULL;

	/* map should be still held by active mmap */
	tmp_fd = bpf_map_get_fd_by_id(data_map_id);
	if (!ASSERT_OK_FD(tmp_fd, "get_map_by_id")) {
		munmap(tmp1, map_sz);
		goto cleanup;
	}
	close(tmp_fd);

	/* this should release data map finally */
	munmap(tmp1, map_sz);

	/* we need to wait for RCU grace period */
	for (i = 0; i < 10000; i++) {
		__u32 id = data_map_id - 1;
		if (bpf_map_get_next_id(id, &id) || id > data_map_id)
			break;
		usleep(1);
	}

	/* should fail to get map FD by non-existing ID */
	tmp_fd = bpf_map_get_fd_by_id(data_map_id);
	if (!ASSERT_ERR_FD(tmp_fd, "get_map_by_id_after")) {
		close(tmp_fd);
		goto cleanup;
	}

cleanup:
	if (bss_mmaped)
		ASSERT_OK(munmap(bss_mmaped, bss_sz), "cleanup munmap bss_mmaped");
	if (map_mmaped)
		ASSERT_OK(munmap(map_mmaped, map_sz), "cleanup munmap map_mmaped");
	test_mmap__destroy(skel);
}
