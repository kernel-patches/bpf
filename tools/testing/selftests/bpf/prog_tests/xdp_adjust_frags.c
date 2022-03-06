// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>

#include "test_xdp_update_frags.skel.h"

static void test_xdp_update_frags(bool force_helper)
{
	int err, prog_fd, max_skb_frags, buf_size, num;
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	struct test_xdp_update_frags *skel;
	__u32 *offset;
	__u8 *buf;
	FILE *f;

	skel = test_xdp_update_frags__open_and_load();
	if (!ASSERT_OK_PTR(skel, "test_xdp_update_frags__open_and_load"))
		return;

	skel->bss->force_helper = force_helper;

	prog_fd = bpf_program__fd(skel->progs.xdp_adjust_frags);

	buf = malloc(128);
	if (!ASSERT_OK_PTR(buf, "alloc buf 128b"))
		goto out;

	memset(buf, 0, 128);
	offset = (__u32 *)buf;
	*offset = 16;
	buf[*offset] = 0xaa;		/* marker at offset 16 (head) */
	buf[*offset + 15] = 0xaa;	/* marker at offset 31 (head) */

	topts.data_in = buf;
	topts.data_out = buf;
	topts.data_size_in = 128;
	topts.data_size_out = 128;

	err = bpf_prog_test_run_opts(prog_fd, &topts);

	/* test_xdp_update_frags: buf[16,31]: 0xaa -> 0xbb */
	ASSERT_OK(err, "xdp_update_frag");
	ASSERT_EQ(topts.retval, XDP_PASS, "xdp_update_frag retval");
	ASSERT_EQ(buf[16], 0xbb, "xdp_update_frag buf[16]");
	ASSERT_EQ(buf[31], 0xbb, "xdp_update_frag buf[31]");
	if (force_helper) {
		ASSERT_EQ(skel->bss->used_dpa, false, "did not use DPA");
		ASSERT_EQ(skel->bss->used_helper, true, "used helper");
	} else {
		ASSERT_EQ(skel->bss->used_dpa, true, "used DPA");
		ASSERT_EQ(skel->bss->used_helper, false, "did not use helper");
	}

	free(buf);

	buf = malloc(9000);
	if (!ASSERT_OK_PTR(buf, "alloc buf 9Kb"))
		goto out;

	memset(buf, 0, 9000);
	offset = (__u32 *)buf;
	*offset = 5000;
	buf[*offset] = 0xaa;		/* marker at offset 5000 (frag0) */
	buf[*offset + 15] = 0xaa;	/* marker at offset 5015 (frag0) */

	topts.data_in = buf;
	topts.data_out = buf;
	topts.data_size_in = 9000;
	topts.data_size_out = 9000;

	err = bpf_prog_test_run_opts(prog_fd, &topts);

	/* test_xdp_update_frags: buf[5000,5015]: 0xaa -> 0xbb */
	ASSERT_OK(err, "xdp_update_frag");
	ASSERT_EQ(topts.retval, XDP_PASS, "xdp_update_frag retval");
	ASSERT_EQ(buf[5000], 0xbb, "xdp_update_frag buf[5000]");
	ASSERT_EQ(buf[5015], 0xbb, "xdp_update_frag buf[5015]");
	if (force_helper) {
		ASSERT_EQ(skel->bss->used_dpa, false, "did not use DPA");
		ASSERT_EQ(skel->bss->used_helper, true, "used helper");
	} else {
		ASSERT_EQ(skel->bss->used_dpa, true, "used DPA");
		ASSERT_EQ(skel->bss->used_helper, false, "did not use helper");
	}

	memset(buf, 0, 9000);
	offset = (__u32 *)buf;
	*offset = 3510;
	buf[*offset] = 0xaa;		/* marker at offset 3510 (head) */
	buf[*offset + 15] = 0xaa;	/* marker at offset 3525 (frag0) */

	err = bpf_prog_test_run_opts(prog_fd, &topts);

	/* test_xdp_update_frags: buf[3510,3525]: 0xaa -> 0xbb */
	ASSERT_OK(err, "xdp_update_frag");
	ASSERT_EQ(topts.retval, XDP_PASS, "xdp_update_frag retval");
	ASSERT_EQ(buf[3510], 0xbb, "xdp_update_frag buf[3510]");
	ASSERT_EQ(buf[3525], 0xbb, "xdp_update_frag buf[3525]");
	ASSERT_EQ(skel->bss->used_dpa, false, "did not use DPA");
	ASSERT_EQ(skel->bss->used_helper, true, "used helper");

	memset(buf, 0, 9000);
	offset = (__u32 *)buf;
	*offset = 7606;
	buf[*offset] = 0xaa;		/* marker at offset 7606 (frag0) */
	buf[*offset + 15] = 0xaa;	/* marker at offset 7621 (frag1) */

	err = bpf_prog_test_run_opts(prog_fd, &topts);

	/* test_xdp_update_frags: buf[7606,7621]: 0xaa -> 0xbb */
	ASSERT_OK(err, "xdp_update_frag");
	ASSERT_EQ(topts.retval, XDP_PASS, "xdp_update_frag retval");
	ASSERT_EQ(buf[7606], 0xbb, "xdp_update_frag buf[7606]");
	ASSERT_EQ(buf[7621], 0xbb, "xdp_update_frag buf[7621]");
	ASSERT_EQ(skel->bss->used_dpa, false, "did not use DPA");
	ASSERT_EQ(skel->bss->used_helper, true, "used helper");

	free(buf);

	/* test_xdp_update_frags: unsupported buffer size */
	f = fopen("/proc/sys/net/core/max_skb_frags", "r");
	if (!ASSERT_OK_PTR(f, "max_skb_frag file pointer"))
		goto out;

	num = fscanf(f, "%d", &max_skb_frags);
	fclose(f);

	if (!ASSERT_EQ(num, 1, "max_skb_frags read failed"))
		goto out;

	/* xdp_buff linear area size is always set to 4096 in the
	 * bpf_prog_test_run_xdp routine.
	 */
	buf_size = 4096 + (max_skb_frags + 1) * sysconf(_SC_PAGE_SIZE);
	buf = malloc(buf_size);
	if (!ASSERT_OK_PTR(buf, "alloc buf"))
		goto out;

	memset(buf, 0, buf_size);
	offset = (__u32 *)buf;
	*offset = 16;
	buf[*offset] = 0xaa;
	buf[*offset + 15] = 0xaa;

	topts.data_in = buf;
	topts.data_out = buf;
	topts.data_size_in = buf_size;
	topts.data_size_out = buf_size;

	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_EQ(err, -ENOMEM,
		  "unsupported buf size, possible non-default /proc/sys/net/core/max_skb_flags?");
	free(buf);
out:
	test_xdp_update_frags__destroy(skel);
}

void test_xdp_adjust_frags(void)
{
	if (test__start_subtest("xdp_adjust_frags-force-nodpa"))
		test_xdp_update_frags(true);
	if (test__start_subtest("xdp_adjust_frags-dpa+memcpy"))
		test_xdp_update_frags(false);
}
