// SPDX-License-Identifier: GPL-2.0

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <test_progs.h>

__u32 get_map_id(struct bpf_object *obj, const char *name)
{
	struct bpf_map_info map_info = {};
	__u32 map_info_len;
	struct bpf_map *map;
	int err;

	map_info_len = sizeof(map_info);

	map = bpf_object__find_map_by_name(obj, name);
	if (!ASSERT_OK_PTR(map, "find map"))
		return 0;

	err = bpf_map_get_info_by_fd(bpf_map__fd(map),
				     &map_info, &map_info_len);
	ASSERT_OK(err, "get map info");
	return map_info.id;
}

void test_pinning(void)
{
	const char *file_invalid = "./test_pinning_invalid.bpf.o";
	const char *custpinpath = "/sys/fs/bpf/custom/pinmap";
	const char *nopinpath = "/sys/fs/bpf/nopinmap";
	const char *nopinpath2 = "/sys/fs/bpf/nopinmap2";
	const char *custpath = "/sys/fs/bpf/custom";
	const char *pinpath = "/sys/fs/bpf/pinmap";
	const char *file = "./test_pinning.bpf.o";
	__u32 map_id, map_id2;
	struct stat statbuf = {};
	struct bpf_object *obj;
	struct bpf_map *map;
	int err, map_fd;
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts,
		.pin_root_path = custpath,
	);

	/* check that opening fails with invalid pinning value in map def */
	obj = bpf_object__open_file(file_invalid, NULL);
	err = libbpf_get_error(obj);
	if (!ASSERT_EQ(err, -EINVAL, "invalid open")) {
		PERROR("bpf_object__open_file");
		obj = NULL;
		goto out;
	}

	/* open the valid object file  */
	obj = bpf_object__open_file(file, NULL);
	err = libbpf_get_error(obj);
	if (!ASSERT_OK(err, "default open")) {
		obj = NULL;
		goto out;
	}

	err = bpf_object__load(obj);
	if (!ASSERT_OK(err, "default load"))
		goto out;

	/* check that pinmap was pinned */
	err = stat(pinpath, &statbuf);
	if (!ASSERT_OK(err, "stat pinpath"))
		goto out;

	/* check that nopinmap was *not* pinned */
	err = stat(nopinpath, &statbuf);
	if (!err || errno != ENOENT) {
		PERROR("stat nopinpath");
		goto out;
	}

	/* check that nopinmap2 was *not* pinned */
	err = stat(nopinpath2, &statbuf);
	if (!err || errno != ENOENT) {
		PERROR("stat nopinpath2");
		goto out;
	}

	map_id = get_map_id(obj, "pinmap");
	if (!map_id)
		goto out;

	bpf_object__close(obj);

	obj = bpf_object__open_file(file, NULL);
	if (!ASSERT_OK(libbpf_get_error(obj), "open BPF object")) {
		obj = NULL;
		goto out;
	}

	err = bpf_object__load(obj);
	if (!ASSERT_OK(err, "default load"))
		goto out;

	/* check that same map ID was reused for second load */
	map_id2 = get_map_id(obj, "pinmap");
	if (!ASSERT_EQ(map_id, map_id2, "check reuse"))
		goto out;

	/* should be no-op to re-pin same map */
	map = bpf_object__find_map_by_name(obj, "pinmap");
	if (!ASSERT_OK_PTR(map, "find map"))
		goto out;

	err = bpf_map__pin(map, NULL);
	if (!ASSERT_OK(err, "re-pin map"))
		goto out;

	/* but error to pin at different location */
	err = bpf_map__pin(map, "/sys/fs/bpf/other");
	if (ASSERT_ERR(err, "pin map different"))
		goto out;

	/* unpin maps with a pin_path set */
	err = bpf_object__unpin_maps(obj, NULL);
	if (!ASSERT_OK(err, "unpin maps"))
		goto out;

	/* and re-pin them... */
	err = bpf_object__pin_maps(obj, NULL);
	if (!ASSERT_OK(err, "pin maps"))
		goto out;

	/* get pinning path */
	if (!ASSERT_STREQ(bpf_map__pin_path(map), pinpath, "get pin path"))
		goto out;

	/* set pinning path of other map and re-pin all */
	map = bpf_object__find_map_by_name(obj, "nopinmap");
	if (!ASSERT_OK_PTR(map, "find map"))
		goto out;

	err = bpf_map__set_pin_path(map, custpinpath);
	if (!ASSERT_OK(err, "set pin path"))
		goto out;

	/* get pinning path after set */
	if (!ASSERT_STREQ(bpf_map__pin_path(map), custpinpath,
			  "get pin path after set"))
		goto out;

	/* should only pin the one unpinned map */
	err = bpf_object__pin_maps(obj, NULL);
	if (!ASSERT_OK(err, "pin maps"))
		goto out;

	/* check that nopinmap was pinned at the custom path */
	err = stat(custpinpath, &statbuf);
	if (!ASSERT_OK(err, "stat custpinpath"))
		goto out;

	/* remove the custom pin path to re-test it with auto-pinning below */
	err = unlink(custpinpath);
	if (!ASSERT_OK(err, "unlink custpinpath"))
		goto out;

	err = rmdir(custpath);
	if (!ASSERT_OK(err, "rmdir custpindir"))
		goto out;

	bpf_object__close(obj);

	/* open the valid object file again */
	obj = bpf_object__open_file(file, NULL);
	err = libbpf_get_error(obj);
	if (!ASSERT_OK(err, "default open")) {
		obj = NULL;
		goto out;
	}

	/* set pin paths so that nopinmap2 will attempt to reuse the map at
	 * pinpath (which will fail), but not before pinmap has already been
	 * reused
	 */
	bpf_object__for_each_map(map, obj) {
		if (!strcmp(bpf_map__name(map), "nopinmap"))
			err = bpf_map__set_pin_path(map, nopinpath2);
		else if (!strcmp(bpf_map__name(map), "nopinmap2"))
			err = bpf_map__set_pin_path(map, pinpath);
		else
			continue;

		if (!ASSERT_OK(err, "set pin path"))
			goto out;
	}

	/* should fail because of map parameter mismatch */
	err = bpf_object__load(obj);
	if (!ASSERT_EQ(err, -EINVAL, "param mismatch load")) {
		PERROR("bpf_object__load");
		goto out;
	}

	/* nopinmap2 should have been pinned and cleaned up again */
	err = stat(nopinpath2, &statbuf);
	if (!err || errno != ENOENT) {
		PERROR("stat nopinpath2");
		goto out;
	}

	/* pinmap should still be there */
	err = stat(pinpath, &statbuf);
	if (!ASSERT_OK(err, "stat pinpath"))
		goto out;

	bpf_object__close(obj);

	/* test auto-pinning at custom path with open opt */
	obj = bpf_object__open_file(file, &opts);
	if (!ASSERT_OK(libbpf_get_error(obj), "open BPF object with opts")) {
		obj = NULL;
		goto out;
	}

	err = bpf_object__load(obj);
	if (!ASSERT_OK(err, "custom load"))
		goto out;

	/* check that pinmap was pinned at the custom path */
	err = stat(custpinpath, &statbuf);
	if (!ASSERT_OK(err, "stat custpinpath"))
		goto out;

	/* remove the custom pin path to re-test it with reuse fd below */
	err = unlink(custpinpath);
	if (!ASSERT_OK(err, "unlink custpinpath"))
		goto out;

	err = rmdir(custpath);
	if (!ASSERT_OK(err, "rmdir custpindir"))
		goto out;

	bpf_object__close(obj);

	/* test pinning at custom path with reuse fd */
	obj = bpf_object__open_file(file, NULL);
	err = libbpf_get_error(obj);
	if (!ASSERT_OK(err, "default open")) {
		obj = NULL;
		goto out;
	}

	map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, NULL, sizeof(__u32),
				sizeof(__u64), 1, NULL);
	if (!ASSERT_OK_FD(map_fd, "create pinmap manually"))
		goto out;

	map = bpf_object__find_map_by_name(obj, "pinmap");
	if (!ASSERT_OK_PTR(map, "find map"))
		goto close_map_fd;

	err = bpf_map__reuse_fd(map, map_fd);
	if (!ASSERT_OK(err, "reuse pinmap fd"))
		goto close_map_fd;

	err = bpf_map__set_pin_path(map, custpinpath);
	if (!ASSERT_OK(err, "set pin path"))
		goto close_map_fd;

	err = bpf_object__load(obj);
	if (!ASSERT_OK(err, "custom load"))
		goto close_map_fd;

	/* check that pinmap was pinned at the custom path */
	err = stat(custpinpath, &statbuf);
	if (!ASSERT_OK(err, "stat custpinpath"))
		goto close_map_fd;

close_map_fd:
	close(map_fd);
out:
	unlink(pinpath);
	unlink(nopinpath);
	unlink(nopinpath2);
	unlink(custpinpath);
	rmdir(custpath);
	if (obj)
		bpf_object__close(obj);
}
