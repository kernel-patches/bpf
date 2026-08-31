// SPDX-License-Identifier: GPL-2.0

#include <errno.h>
#include <linux/ethtool_netlink.h>
#include <linux/genetlink.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <unistd.h>

#include "netlink_helpers.h"
#include "network_helpers.h"
#include "test_progs.h"

#include "genl_lsm.skel.h"

#define NLCTRL_FAMILY_NAME "nlctrl"
#define OTHER_FAMILY_NAME  "ethtool"

/* not probable to encounter this errno in real life */
#define TEST_ERRNO EDOTDOT

static int nlctrl_request(int fd, __u8 cmd, bool dump)
{
	static __u32 sequence = 1;
	struct genl_req req = {};
	__u32 seq = sequence++;
	int err;

	req.nlh.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	req.nlh.nlmsg_type = GENL_ID_CTRL;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | (dump ? NLM_F_DUMP : 0);
	req.nlh.nlmsg_seq = seq;
	req.genl.cmd = cmd;
	req.genl.version = 2;
	if (addattrstrz(&req.nlh, sizeof(req), CTRL_ATTR_FAMILY_NAME, NLCTRL_FAMILY_NAME))
		return -EMSGSIZE;

	err = genl_send(fd, &req.nlh);
	if (err)
		return err;

	return genl_recv(fd, seq, GENL_ID_CTRL, dump);
}

static void test_doit(struct genl_lsm *skel, int fd)
{
	int err;

	skel->bss->target_cmd = CTRL_CMD_GETFAMILY;
	skel->bss->target_flags = 0;
	skel->bss->target_netns_inum = 0;
	skel->bss->allow = true;

	err = nlctrl_request(fd, CTRL_CMD_GETFAMILY, false);
	if (!ASSERT_OK(err, "CTRL_CMD_GETFAMILY (allow)"))
		return;

	skel->bss->allow = false;
	err = nlctrl_request(fd, CTRL_CMD_GETFAMILY, false);
	ASSERT_EQ(err, -TEST_ERRNO, "CTRL_CMD_GETFAMILY (deny)");
}

static void test_dump(struct genl_lsm *skel, int fd)
{
	int err;

	skel->bss->target_cmd = CTRL_CMD_GETPOLICY;
	skel->bss->target_flags = 0;
	skel->bss->target_netns_inum = 0;
	skel->bss->allow = true;

	err = nlctrl_request(fd, CTRL_CMD_GETPOLICY, true);
	if (!ASSERT_OK(err, "allow_getpolicy_dump"))
		return;

	skel->bss->allow = false;
	err = nlctrl_request(fd, CTRL_CMD_GETPOLICY, true);
	ASSERT_EQ(err, -TEST_ERRNO, "deny_getpolicy_dump");
}

static void test_nlmsg_flags(struct genl_lsm *skel, int fd)
{
	int err;

	skel->bss->target_cmd = CTRL_CMD_GETFAMILY;
	skel->bss->target_flags = NLM_F_REQUEST | NLM_F_DUMP;
	skel->bss->target_netns_inum = 0;
	skel->bss->allow = false;

	err = nlctrl_request(fd, CTRL_CMD_GETFAMILY, true);
	ASSERT_EQ(err, -TEST_ERRNO, "deny_dump_flags");

	err = nlctrl_request(fd, CTRL_CMD_GETFAMILY, false);
	ASSERT_OK(err, "doit_flags_not_matched");

	/* now, the other way around */
	skel->bss->target_flags = NLM_F_REQUEST;

	err = nlctrl_request(fd, CTRL_CMD_GETFAMILY, true);
	ASSERT_OK(err, "doit_flags_not_matched");

	err = nlctrl_request(fd, CTRL_CMD_GETFAMILY, false);
	ASSERT_EQ(err, -TEST_ERRNO, "deny_dump_flags");
}

static int other_family_request(int fd, __u16 family_id)
{
	static __u32 sequence = 1000;
	struct genl_req req = {};
	__u32 seq = sequence++;
	int err;

	req.nlh.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	req.nlh.nlmsg_type = family_id;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.nlh.nlmsg_seq = seq;
	req.genl.cmd = ETHTOOL_MSG_LINKSTATE_GET;
	req.genl.version = ETHTOOL_GENL_VERSION;

	err = genl_send(fd, &req.nlh);
	if (err)
		return err;

	return genl_recv(fd, seq, family_id, true);
}

static void test_other_family(struct genl_lsm *skel, int fd, __u16 other_id)
{
	int err;

	skel->bss->target_cmd = 0;
	skel->bss->target_flags = 0;
	skel->bss->target_netns_inum = 0;
	skel->bss->allow = false;

	err = nlctrl_request(fd, CTRL_CMD_GETFAMILY, false);
	if (!ASSERT_EQ(err, -TEST_ERRNO, "nlctrl_denied"))
		return;

	err = other_family_request(fd, other_id);
	ASSERT_OK(err, "other_family_request ok");
}

static __u32 netns_inum(void)
{
	struct stat st;

	if (stat("/proc/self/ns/net", &st))
		return 0;

	return st.st_ino;
}

static void test_netns(struct genl_lsm *skel, int fd)
{
	struct netns_obj *netns = NULL;
	struct nstoken *nstoken = NULL;
	int ns_fd = -1;
	int err;

	SYS_NOFAIL("ip netns del genl_lsm_ns");
	netns = netns_new("genl_lsm_ns", false);
	if (!ASSERT_OK_PTR(netns, "netns_new"))
		return;

	nstoken = open_netns("genl_lsm_ns");
	if (!ASSERT_OK_PTR(nstoken, "open_netns"))
		goto out;

	ns_fd = genl_open(0);
	if (!ASSERT_OK_FD(ns_fd, "genl_open"))
		goto out;

	skel->bss->target_cmd = CTRL_CMD_GETFAMILY;
	skel->bss->target_flags = 0;
	skel->bss->target_netns_inum = netns_inum();
	skel->bss->allow = false;

	if (!ASSERT_NEQ(skel->bss->target_netns_inum, 0, "netns_inum"))
		goto out;

	err = nlctrl_request(ns_fd, CTRL_CMD_GETFAMILY, false);
	ASSERT_EQ(err, -TEST_ERRNO, "denied_in_target_netns");

	close_netns(nstoken);
	nstoken = NULL;

	/* same request, same policy, but now from the original namespace */
	err = nlctrl_request(fd, CTRL_CMD_GETFAMILY, false);
	ASSERT_OK(err, "allowed_outside_target_netns");

out:
	if (ns_fd >= 0)
		close(ns_fd);
	close_netns(nstoken);
	netns_free(netns);
}

void test_genl_lsm(void)
{
	struct genl_lsm *skel;
	int other_id, fd = -1;
	int err;

	skel = genl_lsm__open_and_load();
	if (!ASSERT_OK_PTR(skel, "genl_lsm__open_and_load"))
		return;

	fd = genl_open(0);
	if (!ASSERT_OK_FD(fd, "genl_open"))
		goto cleanup;

	/* do this before attaching our hook, just in case */
	other_id = genl_resolve_family(fd, OTHER_FAMILY_NAME);
	if (other_id == -ENOENT) {
		test__skip();
		goto cleanup;
	}
	if (!ASSERT_GT(other_id, 0, "genl_resolve_family"))
		goto cleanup;

	skel->bss->monitored_pid = getpid();
	err = genl_lsm__attach(skel);
	if (!ASSERT_OK(err, "genl_lsm__attach"))
		goto cleanup;

	if (test__start_subtest("doit"))
		test_doit(skel, fd);
	if (test__start_subtest("dump"))
		test_dump(skel, fd);
	if (test__start_subtest("nlmsg_flags"))
		test_nlmsg_flags(skel, fd);
	if (test__start_subtest("other_family"))
		test_other_family(skel, fd, other_id);
	if (test__start_subtest("netns"))
		test_netns(skel, fd);

cleanup:
	if (fd >= 0)
		close(fd);
	genl_lsm__destroy(skel);
}
