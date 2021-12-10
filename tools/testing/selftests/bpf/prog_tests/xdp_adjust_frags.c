// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>

void test_xdp_update_frags(void)
{
	const char *file = "./test_xdp_update_frags.o";
	__u32 duration, retval, size;
	struct bpf_program *prog;
	struct bpf_object *obj;
	int err, prog_fd;
	__u32 *offset;
	__u8 *buf;

	obj = bpf_object__open(file);
	if (libbpf_get_error(obj))
		return;

	prog = bpf_object__next_program(obj, NULL);
	if (bpf_object__load(obj))
		return;

	prog_fd = bpf_program__fd(prog);

	buf = malloc(128);
	if (CHECK(!buf, "malloc()", "error:%s\n", strerror(errno)))
		goto out;

	memset(buf, 0, 128);
	offset = (__u32 *)buf;
	*offset = 16;
	buf[*offset] = 0xaa;		/* marker at offset 16 (head) */
	buf[*offset + 15] = 0xaa;	/* marker at offset 31 (head) */

	err = bpf_prog_test_run(prog_fd, 1, buf, 128,
				buf, &size, &retval, &duration);

	/* test_xdp_update_frags: buf[16,31]: 0xaa -> 0xbb */
	CHECK(err || retval != XDP_PASS || buf[16] != 0xbb || buf[31] != 0xbb,
	      "128b", "err %d errno %d retval %d size %d\n",
	      err, errno, retval, size);

	free(buf);

	buf = malloc(9000);
	if (CHECK(!buf, "malloc()", "error:%s\n", strerror(errno)))
		goto out;

	memset(buf, 0, 9000);
	offset = (__u32 *)buf;
	*offset = 5000;
	buf[*offset] = 0xaa;		/* marker at offset 5000 (frag0) */
	buf[*offset + 15] = 0xaa;	/* marker at offset 5015 (frag0) */

	err = bpf_prog_test_run(prog_fd, 1, buf, 9000,
				buf, &size, &retval, &duration);

	/* test_xdp_update_frags: buf[5000,5015]: 0xaa -> 0xbb */
	CHECK(err || retval != XDP_PASS ||
	      buf[5000] != 0xbb || buf[5015] != 0xbb,
	      "9000b", "err %d errno %d retval %d size %d\n",
	      err, errno, retval, size);

	memset(buf, 0, 9000);
	offset = (__u32 *)buf;
	*offset = 3510;
	buf[*offset] = 0xaa;		/* marker at offset 3510 (head) */
	buf[*offset + 15] = 0xaa;	/* marker at offset 3525 (frag0) */

	err = bpf_prog_test_run(prog_fd, 1, buf, 9000,
				buf, &size, &retval, &duration);

	/* test_xdp_update_frags: buf[3510,3525]: 0xaa -> 0xbb */
	CHECK(err || retval != XDP_PASS ||
	      buf[3510] != 0xbb || buf[3525] != 0xbb,
	      "9000b", "err %d errno %d retval %d size %d\n",
	      err, errno, retval, size);

	memset(buf, 0, 9000);
	offset = (__u32 *)buf;
	*offset = 7606;
	buf[*offset] = 0xaa;		/* marker at offset 7606 (frag0) */
	buf[*offset + 15] = 0xaa;	/* marker at offset 7621 (frag1) */

	err = bpf_prog_test_run(prog_fd, 1, buf, 9000,
				buf, &size, &retval, &duration);

	/* test_xdp_update_frags: buf[7606,7621]: 0xaa -> 0xbb */
	CHECK(err || retval != XDP_PASS ||
	      buf[7606] != 0xbb || buf[7621] != 0xbb,
	      "9000b", "err %d errno %d retval %d size %d\n",
	      err, errno, retval, size);

	free(buf);
out:
	bpf_object__close(obj);
}

void test_xdp_adjust_frags(void)
{
	if (test__start_subtest("xdp_adjust_frags"))
		test_xdp_update_frags();
}
