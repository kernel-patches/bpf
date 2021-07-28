// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>

void test_xdp_update_frag(void)
{
	const char *file = "./test_xdp_update_frags.o";
	__u32 duration, retval, size;
	struct bpf_object *obj;
	int err, prog_fd;
	__u8 *buf;

	err = bpf_prog_load(file, BPF_PROG_TYPE_XDP, &obj, &prog_fd);
	if (CHECK_FAIL(err))
		return;

	buf = malloc(128);
	if (CHECK(!buf, "malloc()", "error:%s\n", strerror(errno)))
		return;

	memset(buf, 0, 128);

	err = bpf_prog_test_run(prog_fd, 1, buf, 128,
				buf, &size, &retval, &duration);
	free(buf);

	CHECK(err || retval != XDP_DROP,
	      "128b", "err %d errno %d retval %d size %d\n",
	      err, errno, retval, size);

	buf = malloc(9000);
	if (CHECK(!buf, "malloc()", "error:%s\n", strerror(errno)))
		return;

	memset(buf, 0, 9000);
	buf[5000] = 0xaa; /* marker at offset 5000 (frag0) */

	err = bpf_prog_test_run(prog_fd, 1, buf, 9000,
				buf, &size, &retval, &duration);

	/* test_xdp_update_frags: buf[5000]: 0xaa -> 0xbb */
	CHECK(err || retval != XDP_PASS || buf[5000] != 0xbb,
	      "9000b", "err %d errno %d retval %d size %d\n",
	      err, errno, retval, size);

	free(buf);

	bpf_object__close(obj);
}

void test_xdp_adjust_data(void)
{
	if (test__start_subtest("xdp_adjust_data"))
		test_xdp_update_frag();
}
