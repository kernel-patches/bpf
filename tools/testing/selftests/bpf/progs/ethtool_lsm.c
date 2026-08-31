// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"

#include <errno.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

__u32 monitored_pid;
__u32 target_ifindex;
__u32 target_cmd;
__u32 target_sub_cmd;
__u32 target_phy_index;
bool allow;

/*
 * This test is used for all hooks, just checks that it is ours,
 * and allows/denies based on the "allow" global variable
 */
static int test_policy(const struct net_device *dev, __u32 cmd, __u32 sub_cmd, __u32 phy_index)
{
	__u32 pid;

	pid = bpf_get_current_pid_tgid() >> 32;
	if (pid != monitored_pid)
		return 0;

	if (!dev || (target_ifindex && dev->ifindex != target_ifindex))
		return 0;

	if (target_cmd && cmd != target_cmd)
		return 0;

	if (target_sub_cmd && sub_cmd != target_sub_cmd)
		return 0;

	if (phy_index != target_phy_index)
		return -EDOTDOT;

	return allow ? 0 : -EDOTDOT; /* unlikely to see this errno outside this test */
}

SEC("lsm/ethtool_ioctl")
int BPF_PROG(test_ethtool_ioctl, const struct net_device *dev, __u32 cmd, __u32 sub_cmd, int ret)
{
	if (ret)
		return ret;

	return test_policy(dev, cmd, sub_cmd, 0);
}

SEC("lsm/ethtool_netlink_doit")
int BPF_PROG(test_ethtool_doit, const struct net_device *dev, __u32 cmd, __u32 phy_index, int ret)
{
	if (ret)
		return ret;

	return test_policy(dev, cmd, 0, phy_index);
}

SEC("lsm/ethtool_netlink_dump")
int BPF_PROG(test_ethtool_dump, const struct net_device *dev, __u32 cmd, __u32 phy_index, int ret)
{
	if (ret)
		return ret;

	return test_policy(dev, cmd, 0, phy_index);
}

/*
 * The programs below are policy examples for four CVEs. They are
 * load only, and added to illustrate how actual policies might look
 * like for different types of CVEs.
 */

#define ETHTOOL_TEST_CMD		0x0000001aU
#define ETHTOOL_SCHANNELS_CMD		0x0000003dU

static bool is_ixgbe(const struct net_device *dev)
{
	char driver_name[16];
	long len;

	if (!dev || !dev->dev.parent || !dev->dev.parent->driver)
		return false;

	len = bpf_probe_read_kernel_str(driver_name, sizeof(driver_name),
					dev->dev.parent->driver->name);
	if (len < 0)
		return false;

	return bpf_strncmp(driver_name, 6, "ixgbe") == 0;
}

/*
 * CVE-2021-46916 is an example of ioctl-only bug for a particular driver (ixgbe).
 */
SEC("lsm/ethtool_ioctl")
int BPF_PROG(cve_2021_46916, const struct net_device *dev, __u32 cmd, __u32 sub_cmd, int ret)
{
	if (ret)
		return ret;

	if (cmd != ETHTOOL_TEST_CMD)
		return 0;

	return is_ixgbe(dev) ? -EPERM : 0;
}

/*
 * CVE-2025-21701 is an example of a bug which must be mitigated under a lock,
 * as access to dev->reg_state must be protected.
 */
SEC("lsm/ethtool_netlink_doit")
int BPF_PROG(cve_2025_21701, const struct net_device *dev, __u32 cmd, __u32 phy_index, int ret)
{
	if (ret)
		return ret;

	if (!dev)
		return 0;

	return dev->reg_state >= NETREG_UNREGISTERING ?  -ENODEV : 0;
}

/*
 * CVE-2022-50651 is an example of a bug triggered only by .dump, not by .doit.
 */
SEC("lsm/ethtool_netlink_dump")
int BPF_PROG(cve_2022_50651, const struct net_device *dev, __u32 cmd, __u32 phy_index, int ret)
{
	if (ret)
		return ret;

	return cmd == ETHTOOL_MSG_MODULE_EEPROM_GET ? -EPERM : 0;
}

/*
 * CVE-2024-46834 is an example of a bug which requires to filter out both
 * channels: ioctl and netlink. Note that they receive different cmd values.
 */

SEC("lsm/ethtool_ioctl")
int BPF_PROG(cve_2024_46834_ioctl, const struct net_device *dev, __u32 cmd, __u32 sub_cmd, int ret)
{
	if (ret)
		return ret;

	if (cmd == ETHTOOL_SCHANNELS_CMD)
		return -EPERM;

	return 0;
}

SEC("lsm/ethtool_netlink_doit")
int BPF_PROG(cve_2024_46834_doit, const struct net_device *dev, __u32 cmd, __u32 phy_index, int ret)
{
	if (ret)
		return ret;

	if (cmd == ETHTOOL_MSG_CHANNELS_SET)
		return -EPERM;

	return 0;
}

char _license[] SEC("license") = "GPL";
