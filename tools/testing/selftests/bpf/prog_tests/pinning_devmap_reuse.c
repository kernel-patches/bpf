// SPDX-License-Identifier: GPL-2.0

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <test_progs.h>

void test_pinning_devmap_reuse(void)
{
	const char *pinpath1 = "/sys/fs/bpf/pinmap1";
	const char *pinpath2 = "/sys/fs/bpf/pinmap2";
	const char *file = "./test_pinning_devmap.bpf.o";
	struct bpf_object *obj1 = NULL, *obj2 = NULL;
	int err;
	__u32 duration = 0;
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);

	/* load the object a first time */
	obj1 = bpf_object__open_file(file, NULL);
	err = libbpf_get_error(obj1);
	if (CHECK(err, "first open", "err %d\n", err)) {
		obj1 = NULL;
		goto out;
	}
	err = bpf_object__load(obj1);
	if (CHECK(err, "first load", "err %d\n", err))
		goto out;

	/* load the object a second time, re-using the pinned map */
	obj2 = bpf_object__open_file(file, NULL);
	if (CHECK(err, "second open", "err %d\n", err)) {
		obj2 = NULL;
		goto out;
	}
	err = bpf_object__load(obj2);
	if (CHECK(err, "second load", "err %d\n", err))
		goto out;

	/* we can close the reference safely without
	 * the map's refcount falling to 0
	 */
	bpf_object__close(obj1);
	obj1 = NULL;

	/* now, swap the pins */
	err = renameat2(0, pinpath1, 0, pinpath2, RENAME_EXCHANGE);
	if (CHECK(err, "swap pins", "err %d\n", err))
		goto out;

	/* load the object again, this time the re-use should fail */
	obj1 = bpf_object__open_file(file, NULL);
	err = libbpf_get_error(obj1);
	if (CHECK(err, "third open", "err %d\n", err)) {
		obj1 = NULL;
		goto out;
	}
	err = bpf_object__load(obj1);
	if (CHECK(err != -EINVAL, "param mismatch load", "err %d\n", err))
		goto out;

out:
	unlink(pinpath1);
	unlink(pinpath2);
	if (obj1)
		bpf_object__close(obj1);
	if (obj2)
		bpf_object__close(obj2);
}
