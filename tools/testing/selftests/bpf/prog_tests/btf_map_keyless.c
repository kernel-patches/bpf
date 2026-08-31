// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <bpf/btf.h>

/*
 * A hash map with a key-less BTF (btf_key_type_id == 0) used to NULL-deref in
 * btf_type_show() when dumped via bpffs.
 * A fixed kernel rejects such a map at creation; on an unfixed kernel the
 * pin-and-read below deliberately walks that bpffs dump path, so it doubles
 * as a reproducer: it oopses an unfixed kernel (and panics it under
 * panic_on_oops).
 */
static void check_keyless(int map_type, __u32 map_flags, int btf_fd, int val_id)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts);
	const char *path = "/sys/fs/bpf/keyless_map";
	__u32 key = 1, val = 0x41424344;
	char buf[256];
	int map_fd;
	FILE *f;

	opts.map_flags = map_flags;
	opts.btf_fd = btf_fd;
	opts.btf_value_type_id = val_id;

	/*
	 * Positive control: the same map with a real key type must be accepted,
	 * so the -EINVAL below is about the key-less BTF and not some unrelated
	 * rejection (e.g. an unknown map type).
	 */
	opts.btf_key_type_id = val_id;
	map_fd = bpf_map_create(map_type, "keyed_map", 4, 4, 8, &opts);
	if (!ASSERT_GE(map_fd, 0, "keyed create is accepted"))
		return;
	close(map_fd);

	/* A key-less BTF must be rejected. */
	opts.btf_key_type_id = 0;
	map_fd = bpf_map_create(map_type, "keyless_map", 4, 4, 8, &opts);

	if (map_fd >= 0) {
		/* Unfixed kernel: reproduce the oops via the bpffs dump path. */
		(void)bpf_map_update_elem(map_fd, &key, &val, 0);
		if (bpf_obj_pin(map_fd, path) == 0) {
			f = fopen(path, "r");
			if (f) {
				while (fgets(buf, sizeof(buf), f))
					;
				fclose(f);
			}
			unlink(path);
		}
		close(map_fd);
	}

	ASSERT_EQ(map_fd, -EINVAL, "key-less create is rejected");
}

void test_btf_map_keyless(void)
{
	int btf_fd, val_id;
	struct btf *btf;

	btf = btf__new_empty();
	if (!ASSERT_OK_PTR(btf, "btf__new_empty"))
		return;

	val_id = btf__add_int(btf, "int", 4, BTF_INT_SIGNED);
	if (!ASSERT_GT(val_id, 0, "btf__add_int"))
		goto out;

	if (!ASSERT_OK(btf__load_into_kernel(btf), "btf__load_into_kernel"))
		goto out;
	btf_fd = btf__fd(btf);

	if (test__start_subtest("hash"))
		check_keyless(BPF_MAP_TYPE_HASH, 0, btf_fd, val_id);
	if (test__start_subtest("rhash"))
		check_keyless(BPF_MAP_TYPE_RHASH, BPF_F_NO_PREALLOC, btf_fd, val_id);
out:
	btf__free(btf);
}
