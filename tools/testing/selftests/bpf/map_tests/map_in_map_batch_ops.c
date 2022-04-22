// SPDX-License-Identifier: GPL-2.0

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <test_maps.h>

#define OUTER_MAP_ENTRIES 10

static __u32 get_map_id_from_fd(int map_fd)
{
	struct bpf_map_info map_info = {};
	uint32_t info_len = sizeof(map_info);
	int ret;

	ret = bpf_obj_get_info_by_fd(map_fd, &map_info, &info_len);
	CHECK(ret < 0, "Finding map info failed", "error:%s\n",
	      strerror(errno));

	return map_info.id;
}

/* This creates number of OUTER_MAP_ENTRIES maps that will be stored
 * in outer map and return the created map_fds
 */
static void create_inner_maps(enum bpf_map_type map_type,
			      __u32 *inner_map_fds)
{
	int map_fd, map_index, ret;
	__u32 map_key = 0, map_id;
	char map_name[15];

	for (map_index = 0; map_index < OUTER_MAP_ENTRIES; map_index++) {
		memset(map_name, 0, sizeof(map_name));
		sprintf(map_name, "inner_map_fd_%d", map_index);
		map_fd = bpf_map_create(map_type, map_name, sizeof(__u32),
					sizeof(__u32), 1, NULL);
		CHECK(map_fd < 0,
		      "inner bpf_map_create() failed",
		      "map_type=(%d) map_name(%s), error:%s\n",
		      map_type, map_name, strerror(errno));

		/* keep track of the inner map fd as it is required
		 * to add records in outer map
		 */
		inner_map_fds[map_index] = map_fd;

		/* Add entry into this created map
		 * eg: map1 key = 0, value = map1's map id
		 *     map2 key = 0, value = map2's map id
		 */
		map_id = get_map_id_from_fd(map_fd);
		ret = bpf_map_update_elem(map_fd, &map_key, &map_id, 0);
		CHECK(ret != 0,
		      "bpf_map_update_elem failed",
		      "map_type=(%d) map_name(%s), error:%s\n",
		      map_type, map_name, strerror(errno));
	}
}

static int create_outer_map(enum bpf_map_type map_type, __u32 inner_map_fd)
{
	int outer_map_fd;

	LIBBPF_OPTS(bpf_map_create_opts, attr);
	attr.inner_map_fd = inner_map_fd;
	outer_map_fd = bpf_map_create(map_type, "outer_map", sizeof(__u32),
				      sizeof(__u32), OUTER_MAP_ENTRIES,
				      &attr);
	CHECK(outer_map_fd < 0,
	      "outer bpf_map_create()",
	      "map_type=(%d), error:%s\n",
	      map_type, strerror(errno));

	return outer_map_fd;
}

static void validate_fetch_results(int outer_map_fd, __u32 *inner_map_fds,
				   __u32 *fetched_keys, __u32 *fetched_values,
				   __u32 max_entries_fetched)
{
	__u32 inner_map_key, inner_map_value;
	int inner_map_fd, entry, err;
	__u32 outer_map_value;

	for (entry = 0; entry < max_entries_fetched; ++entry) {
		outer_map_value = fetched_values[entry];
		inner_map_fd = bpf_map_get_fd_by_id(outer_map_value);
		CHECK(inner_map_fd < 0,
		      "Failed to get inner map fd",
		      "from id(%d), error=%s\n",
		      outer_map_value, strerror(errno));
		err = bpf_map_get_next_key(inner_map_fd, NULL, &inner_map_key);
		CHECK(err != 0,
		      "Failed to get inner map key",
		      "error=%s\n", strerror(errno));

		err = bpf_map_lookup_elem(inner_map_fd, &inner_map_key,
					  &inner_map_value);
		CHECK(err != 0,
		      "Failed to get inner map value",
		      "for key(%d), error=%s\n",
		      inner_map_key, strerror(errno));

		/* Actual value validation */
		CHECK(outer_map_value != inner_map_value,
		      "Failed to validate inner map value",
		      "fetched(%d) and lookedup(%d)!\n",
		      outer_map_value, inner_map_value);
	}
}

static void fetch_and_validate(int outer_map_fd,
			       __u32 *inner_map_fds,
			       struct bpf_map_batch_opts *opts,
			       __u32 batch_size, bool delete_entries)
{
	__u32 *fetched_keys, *fetched_values, fetched_entries = 0;
	__u32 next_batch_key = 0, step_size = 5;
	int err, retries = 0, max_retries = 3;
	__u32 value_size = sizeof(__u32);

	fetched_keys = calloc(batch_size, value_size);
	fetched_values = calloc(batch_size, value_size);

	while (fetched_entries < batch_size) {
		err = delete_entries
		      ? bpf_map_lookup_and_delete_batch(outer_map_fd,
				      fetched_entries ? &next_batch_key : NULL,
				      &next_batch_key,
				      fetched_keys + fetched_entries,
				      fetched_values + fetched_entries,
				      &step_size, opts)
		      : bpf_map_lookup_batch(outer_map_fd,
				      fetched_entries ? &next_batch_key : NULL,
				      &next_batch_key,
				      fetched_keys + fetched_entries,
				      fetched_values + fetched_entries,
				      &step_size, opts);
		CHECK((err < 0 && (errno != ENOENT && errno != ENOSPC)),
		      "lookup with steps failed",
		      "error: %s\n", strerror(errno));

		fetched_entries += step_size;
		/* retry for max_retries if ENOSPC */
		if (errno == ENOSPC)
			++retries;

		if (retries >= max_retries)
			break;
	}

	CHECK((fetched_entries != batch_size && err != ENOSPC),
	      "Unable to fetch expected entries !",
	      "fetched_entries(%d) and batch_size(%d) error: (%d):%s\n",
	      fetched_entries, batch_size, errno, strerror(errno));

	/* validate the fetched entries */
	validate_fetch_results(outer_map_fd, inner_map_fds, fetched_keys,
			       fetched_values, fetched_entries);
	printf("batch_op is successful for batch_size(%d)\n", batch_size);

	free(fetched_keys);
	free(fetched_values);
}

static void _map_in_map_batch_ops(enum bpf_map_type outer_map_type,
				  enum bpf_map_type inner_map_type)
{
	__u32 *outer_map_keys, *inner_map_fds;
	__u32 max_entries = OUTER_MAP_ENTRIES;
	__u32 value_size = sizeof(__u32);
	int batch_size[2] = {5, 10};
	__u32 map_index, op_index;
	int outer_map_fd, ret;
	DECLARE_LIBBPF_OPTS(bpf_map_batch_opts, opts,
			    .elem_flags = 0,
			    .flags = 0,
	);

	outer_map_keys = calloc(max_entries, value_size);
	inner_map_fds = calloc(max_entries, value_size);
	create_inner_maps(inner_map_type, inner_map_fds);

	outer_map_fd = create_outer_map(outer_map_type, *inner_map_fds);
	/* create outer map keys */
	for (map_index = 0; map_index < max_entries; map_index++)
		outer_map_keys[map_index] =
			((outer_map_type == BPF_MAP_TYPE_ARRAY_OF_MAPS)
			 ? 9 : 1000) - map_index;

	/* batch operation - map_update */
	ret = bpf_map_update_batch(outer_map_fd, outer_map_keys,
				   inner_map_fds, &max_entries, &opts);
	CHECK(ret != 0,
	      "Failed to update the outer map batch ops",
	      "error=%s\n", strerror(errno));

	/* batch operation - map_lookup */
	for (op_index = 0; op_index < 2; ++op_index)
		fetch_and_validate(outer_map_fd, inner_map_fds, &opts,
				   batch_size[op_index], false);

	/* batch operation - map_lookup_delete */
	if (outer_map_type == BPF_MAP_TYPE_HASH_OF_MAPS)
		fetch_and_validate(outer_map_fd, inner_map_fds, &opts,
				   max_entries, true /*delete*/);

	free(inner_map_fds);
	free(outer_map_keys);
}

void test_map_in_map_batch_ops_array(void)
{
	_map_in_map_batch_ops(BPF_MAP_TYPE_ARRAY_OF_MAPS, BPF_MAP_TYPE_ARRAY);
	printf("%s:PASS with inner ARRAY map\n", __func__);
	_map_in_map_batch_ops(BPF_MAP_TYPE_ARRAY_OF_MAPS, BPF_MAP_TYPE_HASH);
	printf("%s:PASS with inner HASH map\n", __func__);
}

void test_map_in_map_batch_ops_hash(void)
{
	_map_in_map_batch_ops(BPF_MAP_TYPE_HASH_OF_MAPS, BPF_MAP_TYPE_ARRAY);
	printf("%s:PASS with inner ARRAY map\n", __func__);
	_map_in_map_batch_ops(BPF_MAP_TYPE_HASH_OF_MAPS, BPF_MAP_TYPE_HASH);
	printf("%s:PASS with inner HASH map\n", __func__);
}
