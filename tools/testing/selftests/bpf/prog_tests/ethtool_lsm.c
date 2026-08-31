// SPDX-License-Identifier: GPL-2.0

#include <errno.h>
#include <linux/ethtool_netlink.h>
#include <linux/genetlink.h>
#include <net/if.h>
#include <stdbool.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "netdevsim_helpers.h"
#include "network_helpers.h"
#include "netlink_helpers.h"
#include "test_progs.h"

#include "ethtool_lsm.skel.h"

/* not probable to encounter this errno in real life */
#define TEST_ERRNO EDOTDOT
#define TEST_PHY_INDEX 1

/* ethtool_netlink_generated.h is not copied to tools/include/uapi. */
#define ETHTOOL_A_MODULE_FW_FLASH_HEADER 1
#define ETHTOOL_MSG_MODULE_FW_FLASH_ACT 44
#define ETHTOOL_A_HEADER_PHY_INDEX 4

static int ethnl_request(int fd, __u16 family_id, __u8 cmd, __u16 hdr_attr,
			 __u16 extra_nest, __u32 ifindex, __u32 phy_index, bool dump)
{
	static __u32 sequence = 10;
	struct genl_req req = {};
	__u32 seq = sequence++;
	struct rtattr *nest;
	int err;

	req.nlh.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	req.nlh.nlmsg_type = family_id;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | (dump ? NLM_F_DUMP : 0);
	req.nlh.nlmsg_seq = seq;
	req.genl.cmd = cmd;
	req.genl.version = ETHTOOL_GENL_VERSION;

	nest = addattr_nest(&req.nlh, sizeof(req), hdr_attr | NLA_F_NESTED);
	if (ifindex && addattr32(&req.nlh, sizeof(req), ETHTOOL_A_HEADER_DEV_INDEX, ifindex))
		return -EMSGSIZE;
	if (phy_index && addattr32(&req.nlh, sizeof(req), ETHTOOL_A_HEADER_PHY_INDEX, phy_index))
		return -EMSGSIZE;
	if (addattr32(&req.nlh, sizeof(req), ETHTOOL_A_HEADER_FLAGS, ETHTOOL_FLAG_COMPACT_BITSETS))
		return -EMSGSIZE;
	addattr_nest_end(&req.nlh, nest);

	if (extra_nest) {
		nest = addattr_nest(&req.nlh, sizeof(req), extra_nest | NLA_F_NESTED);
		addattr_nest_end(&req.nlh, nest);
	}

	err = genl_send(fd, &req.nlh);
	if (err)
		return err;

	return genl_recv(fd, seq, family_id, dump);
}

static int netdev_set_up(__u32 ifindex)
{
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg ifm;
	} req = {
		.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
		.nlh.nlmsg_type = RTM_NEWLINK,
		.nlh.nlmsg_flags = NLM_F_REQUEST,
		.ifm.ifi_family = AF_UNSPEC,
		.ifm.ifi_index = ifindex,
		.ifm.ifi_flags = IFF_UP,
		.ifm.ifi_change = IFF_UP,
	};
	struct rtnl_handle rth;
	int err;

	err = rtnl_open(&rth, 0);
	if (err)
		return err;
	err = rtnl_talk(&rth, &req.nlh, NULL);
	rtnl_close(&rth);

	return err;
}

static int ethtool_ioctl(__u32 ifindex, void *data)
{
	struct ifreq ifr = {};
	int fd, err;

	if (!if_indextoname(ifindex, ifr.ifr_name))
		return -errno;

	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	ifr.ifr_data = data;
	err = ioctl(fd, SIOCETHTOOL, &ifr);
	if (err)
		err = -errno;
	close(fd);

	return err;
}

static void check_doit(struct ethtool_lsm *skel, int fd, __u16 family_id,
		       __u32 ifindex, __u8 cmd, __u16 hdr_attr,
		       __u16 extra_nest, __u32 phy_index)
{
	int err;

	skel->bss->target_ifindex = ifindex;
	skel->bss->target_cmd = cmd;
	skel->bss->target_sub_cmd = 0;
	skel->bss->target_phy_index = phy_index;

	skel->bss->allow = true;
	err = ethnl_request(fd, family_id, cmd, hdr_attr, extra_nest, ifindex, phy_index, false);
	if (!ASSERT_NEQ(err, -TEST_ERRNO, "doit (allow)"))
		return;

	skel->bss->allow = false;
	err = ethnl_request(fd, family_id, cmd, hdr_attr, extra_nest, ifindex, phy_index, false);
	ASSERT_EQ(err, -TEST_ERRNO, "doit (deny)");
}

static void check_dump(struct ethtool_lsm *skel, int fd, __u16 family_id,
		       __u32 ifindex, __u8 cmd, __u16 hdr_attr, bool single_dev,
		       __u32 phy_index)
{
	__u32 req_ifindex = single_dev ? ifindex : 0;
	int err;

	/*
	 * A phy_index which is not present on netdevsim can fail preparation on
	 * the first device in a dump, so match the hook on any device here.
	 */
	skel->bss->target_ifindex = phy_index ? 0 : ifindex;

	skel->bss->target_cmd = cmd;
	skel->bss->target_sub_cmd = 0;
	skel->bss->target_phy_index = phy_index;

	skel->bss->allow = true;
	err = ethnl_request(fd, family_id, cmd, hdr_attr, 0, req_ifindex, phy_index, true);
	if (!ASSERT_NEQ(err, -TEST_ERRNO, "dump (allow)"))
		return;

	skel->bss->allow = false;
	err = ethnl_request(fd, family_id, cmd, hdr_attr, 0, req_ifindex, phy_index, true);
	ASSERT_EQ(err, -TEST_ERRNO, "dump (deny)");
}

static void check_ioctl(struct ethtool_lsm *skel, __u32 ifindex)
{
	struct ethtool_value value = { .cmd = ETHTOOL_GLINK };
	int err;

	skel->bss->target_ifindex = ifindex;
	skel->bss->target_cmd = ETHTOOL_GLINK;
	skel->bss->target_sub_cmd = 0;
	skel->bss->target_phy_index = 0;

	skel->bss->allow = true;
	err = ethtool_ioctl(ifindex, &value);
	if (!ASSERT_NEQ(err, -TEST_ERRNO, "ETHTOOL_GLINK (allow)"))
		return;

	skel->bss->allow = false;
	err = ethtool_ioctl(ifindex, &value);
	ASSERT_EQ(err, -TEST_ERRNO, "ETHTOOL_GLINK (deny)");
}

static void check_ioctl_sub_cmd(struct ethtool_lsm *skel, __u32 ifindex)
{
	struct ethtool_per_queue_op req = { .cmd = ETHTOOL_PERQUEUE };
	int err;

	/*
	 * ETHTOOL_PERQUEUE is the only cmd where sub_cmd differs from cmd,
	 * so try to apply policy only to one sub_cmd of two
	 */
	skel->bss->target_ifindex = ifindex;
	skel->bss->target_cmd = ETHTOOL_PERQUEUE;
	skel->bss->target_sub_cmd = ETHTOOL_SCOALESCE;
	skel->bss->target_phy_index = 0;
	skel->bss->allow = false;

	req.sub_command = ETHTOOL_SCOALESCE;
	err = ethtool_ioctl(ifindex, &req);
	ASSERT_EQ(err, -TEST_ERRNO, "ETHTOOL_SCOALESCE");

	/* this fails in any case on netdevsim, but the errno is not ours => success */
	req.sub_command = ETHTOOL_GCOALESCE;
	ASSERT_NEQ(ethtool_ioctl(ifindex, &req), -TEST_ERRNO, "ETHTOOL_GCOALESCE");
}

void test_ethtool_lsm(void)
{
	__u32 netdevsim_ifindex;
	struct ethtool_lsm *skel = NULL;
	struct netns_obj *netns = NULL;
	struct nstoken *nstoken = NULL;
	int netdevsim_id = -1, family_id, fd = -1, err;

	SYS_NOFAIL("ip netns del ethtool_lsm_ns");
	netns = netns_new("ethtool_lsm_ns", false);
	if (!ASSERT_OK_PTR(netns, "netns_new"))
		goto out;

	nstoken = open_netns("ethtool_lsm_ns");
	if (!ASSERT_OK_PTR(nstoken, "open_netns"))
		goto out;

	netdevsim_id = netdevsim_create(&netdevsim_ifindex);
	if (!ASSERT_GE(netdevsim_id, 0, "netdevsim_create"))
		goto out;

	err = netdev_set_up(netdevsim_ifindex);
	if (!ASSERT_OK(err, "netdev_set_up"))
		goto out;

	skel = ethtool_lsm__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		goto out;

	/* load-only examples */
	bpf_program__set_autoattach(skel->progs.cve_2021_46916, false);
	bpf_program__set_autoattach(skel->progs.cve_2025_21701, false);
	bpf_program__set_autoattach(skel->progs.cve_2022_50651, false);
	bpf_program__set_autoattach(skel->progs.cve_2024_46834_ioctl, false);
	bpf_program__set_autoattach(skel->progs.cve_2024_46834_doit, false);

	skel->bss->monitored_pid = getpid();

	err = ethtool_lsm__attach(skel);
	if (!ASSERT_OK(err, "attach"))
		goto out;

	fd = genl_open(0);
	if (!ASSERT_OK_FD(fd, "genl_open"))
		goto out;

	family_id = genl_resolve_family(fd, ETHTOOL_GENL_NAME);
	if (family_id == -ENOENT) {
		test__skip();
		goto out;
	}
	if (!ASSERT_GT(family_id, 0, "resolve_ethtool_family"))
		goto out;

	if (test__start_subtest("linkstate_get_doit"))
		check_doit(skel, fd, family_id, netdevsim_ifindex,
			   ETHTOOL_MSG_LINKSTATE_GET, ETHTOOL_A_LINKSTATE_HEADER, 0, 0);

	if (test__start_subtest("linkstate_get_dump"))
		check_dump(skel, fd, family_id, netdevsim_ifindex,
			   ETHTOOL_MSG_LINKSTATE_GET, ETHTOOL_A_LINKSTATE_HEADER, false, 0);

	if (test__start_subtest("cable_test_act"))
		check_doit(skel, fd, family_id, netdevsim_ifindex,
			   ETHTOOL_MSG_CABLE_TEST_ACT, ETHTOOL_A_CABLE_TEST_HEADER, 0, 0);

	if (test__start_subtest("cable_test_tdr_act"))
		check_doit(skel, fd, family_id, netdevsim_ifindex,
			   ETHTOOL_MSG_CABLE_TEST_TDR_ACT,
			   ETHTOOL_A_CABLE_TEST_TDR_HEADER, 0, 0);

	if (test__start_subtest("features_set"))
		check_doit(skel, fd, family_id, netdevsim_ifindex,
			   ETHTOOL_MSG_FEATURES_SET, ETHTOOL_A_FEATURES_HEADER,
			   ETHTOOL_A_FEATURES_WANTED, 0);

	if (test__start_subtest("module_fw_flash_act"))
		check_doit(skel, fd, family_id, netdevsim_ifindex,
			   ETHTOOL_MSG_MODULE_FW_FLASH_ACT,
			   ETHTOOL_A_MODULE_FW_FLASH_HEADER, 0, 0);

	if (test__start_subtest("tunnel_info_get_doit"))
		check_doit(skel, fd, family_id, netdevsim_ifindex,
			   ETHTOOL_MSG_TUNNEL_INFO_GET, ETHTOOL_A_TUNNEL_INFO_HEADER, 0, 0);

	if (test__start_subtest("tunnel_info_get_dump"))
		check_dump(skel, fd, family_id, netdevsim_ifindex,
			   ETHTOOL_MSG_TUNNEL_INFO_GET, ETHTOOL_A_TUNNEL_INFO_HEADER,
			   false, 0);

	if (test__start_subtest("tsinfo_get_dump"))
		check_dump(skel, fd, family_id, netdevsim_ifindex,
			   ETHTOOL_MSG_TSINFO_GET, ETHTOOL_A_TSINFO_HEADER, true, 0);

	if (test__start_subtest("rss_get_dump"))
		check_dump(skel, fd, family_id, netdevsim_ifindex,
			   ETHTOOL_MSG_RSS_GET, ETHTOOL_A_RSS_HEADER, true, 0);

	if (test__start_subtest("channels_set_doit"))
		check_doit(skel, fd, family_id, netdevsim_ifindex,
			   ETHTOOL_MSG_CHANNELS_SET, ETHTOOL_A_CHANNELS_HEADER, 0, 0);

	if (test__start_subtest("cable_test_phy_index"))
		check_doit(skel, fd, family_id, netdevsim_ifindex,
			   ETHTOOL_MSG_CABLE_TEST_ACT, ETHTOOL_A_CABLE_TEST_HEADER,
			   0, TEST_PHY_INDEX);

	if (test__start_subtest("strset_get_phy_index_dump"))
		check_dump(skel, fd, family_id, netdevsim_ifindex,
			   ETHTOOL_MSG_STRSET_GET, ETHTOOL_A_STRSET_HEADER, true,
			   TEST_PHY_INDEX);

	if (test__start_subtest("ioctl"))
		check_ioctl(skel, netdevsim_ifindex);

	if (test__start_subtest("ioctl_sub_cmd"))
		check_ioctl_sub_cmd(skel, netdevsim_ifindex);

out:
	if (fd >= 0)
		close(fd);
	ethtool_lsm__destroy(skel);
	if (netdevsim_id >= 0)
		netdevsim_destroy(netdevsim_id);
	close_netns(nstoken);
	netns_free(netns);
}
