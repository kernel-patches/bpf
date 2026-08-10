// SPDX-License-Identifier: GPL-2.0
#include <net/if.h>
#include <linux/if_link.h>
#include <test_progs.h>
#include <network_helpers.h>

#define LOCAL_NETNS "xdp_dev_bound_only_netns"
#define LINK_UPDATE_NETNS "xdp_dev_bound_only_lu_netns"

static int load_dummy_prog(char *name, __u32 ifindex, __u32 flags)
{
	struct bpf_insn insns[] = { BPF_MOV64_IMM(BPF_REG_0, 0), BPF_EXIT_INSN() };
	LIBBPF_OPTS(bpf_prog_load_opts, opts);

	opts.prog_flags = flags;
	opts.prog_ifindex = ifindex;
	return bpf_prog_load(BPF_PROG_TYPE_XDP, name, "GPL", insns, ARRAY_SIZE(insns), &opts);
}

/* A test case for bpf_offload_netdev->offload handling bug:
 * - create a veth device (does not support offload);
 * - create a device bound XDP program with BPF_F_XDP_DEV_BOUND_ONLY flag
 *   (such programs are not offloaded);
 * - create a device bound XDP program without flags (such programs are offloaded).
 * This might lead to 'BUG: kernel NULL pointer dereference'.
 */
void test_xdp_dev_bound_only_offdev(void)
{
	struct nstoken *tok = NULL;
	__u32 ifindex;
	int fd1 = -1;
	int fd2 = -1;

	SYS(out, "ip netns add " LOCAL_NETNS);
	tok = open_netns(LOCAL_NETNS);
	if (!ASSERT_OK_PTR(tok, "open_netns"))
		goto out;
	SYS(out, "ip link add eth42 type veth");
	ifindex = if_nametoindex("eth42");
	if (!ASSERT_NEQ(ifindex, 0, "if_nametoindex")) {
		perror("if_nametoindex");
		goto out;
	}
	fd1 = load_dummy_prog("dummy1", ifindex, BPF_F_XDP_DEV_BOUND_ONLY);
	if (!ASSERT_GE(fd1, 0, "load_dummy_prog #1")) {
		perror("load_dummy_prog #1");
		goto out;
	}
	/* Program with ifindex is considered offloaded, however veth
	 * does not support offload => error should be reported.
	 */
	fd2 = load_dummy_prog("dummy2", ifindex, 0);
	ASSERT_EQ(fd2, -EINVAL, "load_dummy_prog #2 (offloaded)");

out:
	close(fd1);
	close(fd2);
	close_netns(tok);
	/* eth42 was added inside netns, removing the netns will
	 * also remove eth42 veth pair.
	 */
	SYS_NOFAIL("ip netns del " LOCAL_NETNS);
}

/* A device-bound program must not run on the XDP software path.
 * dev_xdp_attach() rejected such programs, but bpf_xdp_link_update() reaches
 * dev_xdp_install() directly and bypasses it, so the check has to live in
 * dev_xdp_install(). Create a generic (SKB) XDP link with a normal program,
 * then try to swap in a device-bound program via BPF_LINK_UPDATE.
 */
void test_xdp_dev_bound_only_link_update(void)
{
	LIBBPF_OPTS(bpf_link_create_opts, lopts, .flags = XDP_FLAGS_SKB_MODE);
	int base_fd = -1, devbound_fd = -1, link_fd = -1;
	struct nstoken *tok = NULL;
	__u32 ifindex;
	int err;

	SYS(out, "ip netns add " LINK_UPDATE_NETNS);
	tok = open_netns(LINK_UPDATE_NETNS);
	if (!ASSERT_OK_PTR(tok, "open_netns"))
		goto out;

	SYS(out, "ip link add eth42 type veth");
	ifindex = if_nametoindex("eth42");
	if (!ASSERT_NEQ(ifindex, 0, "if_nametoindex"))
		goto out;

	devbound_fd = load_dummy_prog("devbound", ifindex, BPF_F_XDP_DEV_BOUND_ONLY);
	if (!ASSERT_GE(devbound_fd, 0, "load_dummy_prog devbound"))
		goto out;

	base_fd = load_dummy_prog("base", 0, 0);
	if (!ASSERT_GE(base_fd, 0, "load_dummy_prog base"))
		goto out;

	link_fd = bpf_link_create(base_fd, ifindex, BPF_XDP, &lopts);
	if (!ASSERT_GE(link_fd, 0, "bpf_link_create"))
		goto out;

	err = bpf_link_update(link_fd, devbound_fd, NULL);
	ASSERT_EQ(err, -EINVAL, "link_update device-bound rejected");

out:
	close(link_fd);
	close(base_fd);
	close(devbound_fd);
	close_netns(tok);
	SYS_NOFAIL("ip netns del " LINK_UPDATE_NETNS);
}
