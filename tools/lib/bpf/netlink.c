// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2018 Facebook */

#include <stdlib.h>
#include <memory.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <errno.h>
#include <time.h>

#include "bpf.h"
#include "libbpf.h"
#include "libbpf_internal.h"
#include "nlattr.h"

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

typedef int (*libbpf_dump_nlmsg_t)(void *cookie, void *msg, struct nlattr **tb);

typedef int (*__dump_nlmsg_t)(struct nlmsghdr *nlmsg, libbpf_dump_nlmsg_t,
			      void *cookie);

struct xdp_id_md {
	int ifindex;
	__u32 flags;
	struct xdp_link_info info;
};

static int libbpf_netlink_open(__u32 *nl_pid)
{
	struct sockaddr_nl sa;
	socklen_t addrlen;
	int one = 1, ret;
	int sock;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;

	sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (sock < 0)
		return -errno;

	if (setsockopt(sock, SOL_NETLINK, NETLINK_EXT_ACK,
		       &one, sizeof(one)) < 0) {
		pr_warn("Netlink error reporting not supported\n");
	}

	if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		ret = -errno;
		goto cleanup;
	}

	addrlen = sizeof(sa);
	if (getsockname(sock, (struct sockaddr *)&sa, &addrlen) < 0) {
		ret = -errno;
		goto cleanup;
	}

	if (addrlen != sizeof(sa)) {
		ret = -LIBBPF_ERRNO__INTERNAL;
		goto cleanup;
	}

	*nl_pid = sa.nl_pid;
	return sock;

cleanup:
	close(sock);
	return ret;
}

enum {
	NL_CONT,
	NL_NEXT,
	NL_DONE,
};

static int bpf_netlink_recv(int sock, __u32 nl_pid, int seq,
			    __dump_nlmsg_t _fn, libbpf_dump_nlmsg_t fn,
			    void *cookie)
{
	bool multipart = true;
	struct nlmsgerr *err;
	struct nlmsghdr *nh;
	char buf[4096];
	int len, ret;

	while (multipart) {
start:
		multipart = false;
		len = recv(sock, buf, sizeof(buf), 0);
		if (len < 0) {
			ret = -errno;
			goto done;
		}

		if (len == 0)
			break;

		for (nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, len);
		     nh = NLMSG_NEXT(nh, len)) {
			if (nh->nlmsg_pid != nl_pid) {
				ret = -LIBBPF_ERRNO__WRNGPID;
				goto done;
			}
			if (nh->nlmsg_seq != seq) {
				ret = -LIBBPF_ERRNO__INVSEQ;
				goto done;
			}
			if (nh->nlmsg_flags & NLM_F_MULTI)
				multipart = true;
			switch (nh->nlmsg_type) {
			case NLMSG_ERROR:
				err = (struct nlmsgerr *)NLMSG_DATA(nh);
				if (!err->error)
					continue;
				ret = err->error;
				libbpf_nla_dump_errormsg(nh);
				goto done;
			case NLMSG_DONE:
				return 0;
			default:
				break;
			}
			if (_fn) {
				ret = _fn(nh, fn, cookie);
				if (ret < 0)
					return ret;
				switch (ret) {
				case NL_CONT:
					break;
				case NL_NEXT:
					goto start;
				case NL_DONE:
					return 0;
				default:
					return ret;
				}
			}
		}
	}
	ret = 0;
done:
	return ret;
}

static int libbpf_nl_send_recv(struct nlmsghdr *nh, __dump_nlmsg_t parse_msg,
			       libbpf_dump_nlmsg_t parse_attr, void *cookie);

static int __bpf_set_link_xdp_fd_replace(int ifindex, int fd, int old_fd,
					 __u32 flags)
{
	struct nlattr *nla;
	int ret;
	struct {
		struct nlmsghdr  nh;
		struct ifinfomsg ifinfo;
		char             attrbuf[64];
	} req;

	memset(&req, 0, sizeof(req));
	req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nh.nlmsg_type = RTM_SETLINK;
	req.ifinfo.ifi_family = AF_UNSPEC;
	req.ifinfo.ifi_index = ifindex;

	/* started nested attribute for XDP */
	nla = nlattr_begin_nested(&req.nh, sizeof(req), IFLA_XDP);
	if (!nla)
		return -EMSGSIZE;

	/* add XDP fd */
	ret = nlattr_add(&req.nh, sizeof(req), IFLA_XDP_FD, &fd, sizeof(fd));
	if (ret < 0)
		return ret;

	/* if user passed in any flags, add those too */
	if (flags) {
		ret = nlattr_add(&req.nh, sizeof(req), IFLA_XDP_FLAGS, &flags, sizeof(flags));
		if (ret < 0)
			return ret;
	}

	if (flags & XDP_FLAGS_REPLACE) {
		ret = nlattr_add(&req.nh, sizeof(req), IFLA_XDP_EXPECTED_FD, &old_fd,
				 sizeof(old_fd));
		if (ret < 0)
			return ret;
	}

	nlattr_end_nested(&req.nh, nla);

	return libbpf_nl_send_recv(&req.nh, NULL, NULL, NULL);
}

int bpf_set_link_xdp_fd_opts(int ifindex, int fd, __u32 flags,
			     const struct bpf_xdp_set_link_opts *opts)
{
	int old_fd = -1;

	if (!OPTS_VALID(opts, bpf_xdp_set_link_opts))
		return -EINVAL;

	if (OPTS_HAS(opts, old_fd)) {
		old_fd = OPTS_GET(opts, old_fd, -1);
		flags |= XDP_FLAGS_REPLACE;
	}

	return __bpf_set_link_xdp_fd_replace(ifindex, fd,
					     old_fd,
					     flags);
}

int bpf_set_link_xdp_fd(int ifindex, int fd, __u32 flags)
{
	return __bpf_set_link_xdp_fd_replace(ifindex, fd, 0, flags);
}

static int __dump_link_nlmsg(struct nlmsghdr *nlh,
			     libbpf_dump_nlmsg_t dump_link_nlmsg, void *cookie)
{
	struct nlattr *tb[IFLA_MAX + 1], *attr;
	struct ifinfomsg *ifi = NLMSG_DATA(nlh);
	int len;

	len = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi));
	attr = (struct nlattr *) ((void *) ifi + NLMSG_ALIGN(sizeof(*ifi)));
	if (libbpf_nla_parse(tb, IFLA_MAX, attr, len, NULL) != 0)
		return -LIBBPF_ERRNO__NLPARSE;

	return dump_link_nlmsg(cookie, ifi, tb);
}

static int get_xdp_info(void *cookie, void *msg, struct nlattr **tb)
{
	struct nlattr *xdp_tb[IFLA_XDP_MAX + 1];
	struct xdp_id_md *xdp_id = cookie;
	struct ifinfomsg *ifinfo = msg;
	int ret;

	if (xdp_id->ifindex && xdp_id->ifindex != ifinfo->ifi_index)
		return 0;

	if (!tb[IFLA_XDP])
		return 0;

	ret = libbpf_nla_parse_nested(xdp_tb, IFLA_XDP_MAX, tb[IFLA_XDP], NULL);
	if (ret)
		return ret;

	if (!xdp_tb[IFLA_XDP_ATTACHED])
		return 0;

	xdp_id->info.attach_mode = libbpf_nla_getattr_u8(
		xdp_tb[IFLA_XDP_ATTACHED]);

	if (xdp_id->info.attach_mode == XDP_ATTACHED_NONE)
		return 0;

	if (xdp_tb[IFLA_XDP_PROG_ID])
		xdp_id->info.prog_id = libbpf_nla_getattr_u32(
			xdp_tb[IFLA_XDP_PROG_ID]);

	if (xdp_tb[IFLA_XDP_SKB_PROG_ID])
		xdp_id->info.skb_prog_id = libbpf_nla_getattr_u32(
			xdp_tb[IFLA_XDP_SKB_PROG_ID]);

	if (xdp_tb[IFLA_XDP_DRV_PROG_ID])
		xdp_id->info.drv_prog_id = libbpf_nla_getattr_u32(
			xdp_tb[IFLA_XDP_DRV_PROG_ID]);

	if (xdp_tb[IFLA_XDP_HW_PROG_ID])
		xdp_id->info.hw_prog_id = libbpf_nla_getattr_u32(
			xdp_tb[IFLA_XDP_HW_PROG_ID]);

	return 0;
}


int bpf_get_link_xdp_info(int ifindex, struct xdp_link_info *info,
			  size_t info_size, __u32 flags)
{
	struct xdp_id_md xdp_id = {};
	__u32 mask;
	int ret;
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg ifm;
	} req = {
		.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
		.nlh.nlmsg_type = RTM_GETLINK,
		.nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST,
		.ifm.ifi_family = AF_PACKET,
	};

	if (flags & ~XDP_FLAGS_MASK || !info_size)
		return -EINVAL;

	/* Check whether the single {HW,DRV,SKB} mode is set */
	flags &= (XDP_FLAGS_SKB_MODE | XDP_FLAGS_DRV_MODE | XDP_FLAGS_HW_MODE);
	mask = flags - 1;
	if (flags && flags & mask)
		return -EINVAL;

	xdp_id.ifindex = ifindex;
	xdp_id.flags = flags;

	ret = libbpf_nl_send_recv(&req.nlh, __dump_link_nlmsg, get_xdp_info, &xdp_id);
	if (!ret) {
		size_t sz = min(info_size, sizeof(xdp_id.info));

		memcpy(info, &xdp_id.info, sz);
		memset((void *) info + sz, 0, info_size - sz);
	}

	return ret;
}

static __u32 get_xdp_id(struct xdp_link_info *info, __u32 flags)
{
	flags &= XDP_FLAGS_MODES;

	if (info->attach_mode != XDP_ATTACHED_MULTI && !flags)
		return info->prog_id;
	if (flags & XDP_FLAGS_DRV_MODE)
		return info->drv_prog_id;
	if (flags & XDP_FLAGS_HW_MODE)
		return info->hw_prog_id;
	if (flags & XDP_FLAGS_SKB_MODE)
		return info->skb_prog_id;

	return 0;
}

int bpf_get_link_xdp_id(int ifindex, __u32 *prog_id, __u32 flags)
{
	struct xdp_link_info info;
	int ret;

	ret = bpf_get_link_xdp_info(ifindex, &info, sizeof(info), flags);
	if (!ret)
		*prog_id = get_xdp_id(&info, flags);

	return ret;
}

static int libbpf_nl_send_recv(struct nlmsghdr *nh, __dump_nlmsg_t parse_msg,
			       libbpf_dump_nlmsg_t parse_attr, void *cookie)
{
	__u32 nl_pid = 0;
	int sock, ret;

	if (!nh)
		return -EINVAL;

	sock = libbpf_netlink_open(&nl_pid);
	if (sock < 0)
		return sock;

	nh->nlmsg_pid = 0;
	nh->nlmsg_seq = time(NULL);
	if (send(sock, nh, nh->nlmsg_len, 0) < 0) {
		ret = -errno;
		goto end;
	}

	ret = bpf_netlink_recv(sock, nl_pid, nh->nlmsg_seq, parse_msg, parse_attr, cookie);

end:
	close(sock);
	return ret;
}

/* TC-HOOK */

typedef int (*qdisc_config_t)(struct nlmsghdr *nh, struct tcmsg *t,
			      size_t maxsz);

static int clsact_config(struct nlmsghdr *nh, struct tcmsg *t, size_t maxsz)
{
	t->tcm_parent = TC_H_CLSACT;
	t->tcm_handle = TC_H_MAKE(TC_H_CLSACT, 0);

	return nlattr_add(nh, maxsz, TCA_KIND, "clsact", sizeof("clsact"));
}

static int attach_point_to_config(struct bpf_tc_hook *hook, qdisc_config_t *configp)
{
	switch (OPTS_GET(hook, attach_point, 0)) {
	case BPF_TC_INGRESS:
	case BPF_TC_EGRESS:
	case BPF_TC_INGRESS | BPF_TC_EGRESS:
		if (OPTS_GET(hook, parent, 0))
			return -EINVAL;
		*configp = &clsact_config;
		return 0;
	case BPF_TC_CUSTOM:
		return -EOPNOTSUPP;
	default:
		return -EINVAL;
	}
}

static long long tc_get_tcm_parent(enum bpf_tc_attach_point attach_point,
				       __u32 parent)
{
	switch (attach_point) {
	case BPF_TC_INGRESS:
		if (parent)
			return -EINVAL;
		return TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS);
	case BPF_TC_EGRESS:
		if (parent)
			return -EINVAL;
		return TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS);
	case BPF_TC_CUSTOM:
		if (!parent)
			return -EINVAL;
		return parent;
	default:
		return -EINVAL;
	}
}

static int tc_qdisc_modify(struct bpf_tc_hook *hook, int cmd, int flags)
{
	qdisc_config_t config;
	int ret;
	struct {
		struct nlmsghdr nh;
		struct tcmsg t;
		char buf[256];
	} req;

	ret = attach_point_to_config(hook, &config);
	if (ret < 0)
		return ret;

	memset(&req, 0, sizeof(req));
	req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
	req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | flags;
	req.nh.nlmsg_type = cmd;
	req.t.tcm_family = AF_UNSPEC;
	req.t.tcm_ifindex = OPTS_GET(hook, ifindex, 0);

	ret = config(&req.nh, &req.t, sizeof(req));
	if (ret < 0)
		return ret;

	return libbpf_nl_send_recv(&req.nh, NULL, NULL, NULL);
}

static int tc_qdisc_create_excl(struct bpf_tc_hook *hook)
{
	return tc_qdisc_modify(hook, RTM_NEWQDISC, NLM_F_CREATE);
}

static int tc_qdisc_delete(struct bpf_tc_hook *hook)
{
	return tc_qdisc_modify(hook, RTM_DELQDISC, 0);
}

int bpf_tc_hook_create(struct bpf_tc_hook *hook)
{
	int ifindex;

	if (!hook || !OPTS_VALID(hook, bpf_tc_hook))
		return -EINVAL;

	ifindex = OPTS_GET(hook, ifindex, 0);

	if (ifindex <= 0)
		return -EINVAL;

	return tc_qdisc_create_excl(hook);
}

static int tc_cls_detach(const struct bpf_tc_hook *hook, const struct bpf_tc_opts *opts,
			 bool flush);

int bpf_tc_hook_destroy(struct bpf_tc_hook *hook)
{
	if (!hook || !OPTS_VALID(hook, bpf_tc_hook) || OPTS_GET(hook, ifindex, 0) <= 0)
		return -EINVAL;

	switch (OPTS_GET(hook, attach_point, 0)) {
	case BPF_TC_INGRESS:
	case BPF_TC_EGRESS:
		return tc_cls_detach(hook, NULL, true);
	case BPF_TC_INGRESS | BPF_TC_EGRESS:
		return tc_qdisc_delete(hook);
	case BPF_TC_CUSTOM:
		return -EOPNOTSUPP;
	default:
		return -EINVAL;
	}
}

struct pass_info {
	struct bpf_tc_opts *opts;
	bool processed;
};

/* TC-BPF */

static int tc_cls_add_fd_and_name(struct nlmsghdr *nh, size_t maxsz, int fd)
{
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	char name[256];
	int len, ret;

	ret = bpf_obj_get_info_by_fd(fd, &info, &info_len);
	if (ret < 0)
		return ret;

	ret = nlattr_add(nh, maxsz, TCA_BPF_FD, &fd, sizeof(fd));
	if (ret < 0)
		return ret;

	len = snprintf(name, sizeof(name), "%s:[%u]", info.name, info.id);
	if (len < 0)
		return -errno;
	if (len >= sizeof(name))
		return -ENAMETOOLONG;

	return nlattr_add(nh, maxsz, TCA_BPF_NAME, name, len + 1);
}


static int cls_get_info(struct nlmsghdr *nh, libbpf_dump_nlmsg_t fn, void *cookie);

int bpf_tc_attach(const struct bpf_tc_hook *hook, struct bpf_tc_opts *opts)
{
	__u32 protocol, bpf_flags, handle, priority, parent, prog_id, flags;
	int ret, ifindex, attach_point, prog_fd;
	struct pass_info info = {};
	long long tcm_parent;
	struct nlattr *nla;
	struct {
		struct nlmsghdr nh;
		struct tcmsg t;
		char buf[256];
	} req;

	if (!hook || !opts || !OPTS_VALID(hook, bpf_tc_hook) || !OPTS_VALID(opts, bpf_tc_opts))
		return -EINVAL;

	ifindex = OPTS_GET(hook, ifindex, 0);
	parent = OPTS_GET(hook, parent, 0);
	attach_point = OPTS_GET(hook, attach_point, 0);

	handle = OPTS_GET(opts, handle, 0);
	priority = OPTS_GET(opts, priority, 0);
	prog_fd = OPTS_GET(opts, prog_fd, 0);
	prog_id = OPTS_GET(opts, prog_id, 0);
	flags = OPTS_GET(opts, flags, 0);

	if (ifindex <= 0 || !prog_fd || prog_id)
		return -EINVAL;
	if (priority > UINT16_MAX)
		return -EINVAL;
	if (flags & ~BPF_TC_F_REPLACE)
		return -EINVAL;

	protocol = ETH_P_ALL;
	flags = (flags & BPF_TC_F_REPLACE) ? NLM_F_REPLACE : NLM_F_EXCL;

	memset(&req, 0, sizeof(req));
	req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
	req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_ECHO | flags;
	req.nh.nlmsg_type = RTM_NEWTFILTER;
	req.t.tcm_family = AF_UNSPEC;
	req.t.tcm_handle = handle;
	req.t.tcm_ifindex = ifindex;
	req.t.tcm_info = TC_H_MAKE(priority << 16, htons(protocol));

	tcm_parent = tc_get_tcm_parent(attach_point, parent);
	if (tcm_parent < 0)
		return tcm_parent;
	req.t.tcm_parent = tcm_parent;

	ret = nlattr_add(&req.nh, sizeof(req), TCA_KIND, "bpf", sizeof("bpf"));
	if (ret < 0)
		return ret;

	nla = nlattr_begin_nested(&req.nh, sizeof(req), TCA_OPTIONS);
	if (!nla)
		return -EMSGSIZE;

	ret = tc_cls_add_fd_and_name(&req.nh, sizeof(req), prog_fd);
	if (ret < 0)
		return ret;

	/* direct action mode is always enabled */
	bpf_flags = TCA_BPF_FLAG_ACT_DIRECT;
	ret = nlattr_add(&req.nh, sizeof(req), TCA_BPF_FLAGS, &bpf_flags, sizeof(bpf_flags));
	if (ret < 0)
		return ret;

	nlattr_end_nested(&req.nh, nla);

	info.opts = opts;

	ret = libbpf_nl_send_recv(&req.nh, &cls_get_info, NULL, &info);
	if (ret < 0)
		return ret;

	/* Failed to process unicast response */
	if (!info.processed)
		return -ENOENT;

	return ret;
}

static int tc_cls_detach(const struct bpf_tc_hook *hook, const struct bpf_tc_opts *opts,
			 bool flush)
{
	__u32 protocol = 0, handle, priority, parent, prog_id, flags;
	int ret, ifindex, attach_point, prog_fd;
	long long tcm_parent;
	struct {
		struct nlmsghdr nh;
		struct tcmsg t;
		char buf[256];
	} req;

	if (!hook || !OPTS_VALID(hook, bpf_tc_hook) || !OPTS_VALID(opts, bpf_tc_opts))
		return -EINVAL;

	ifindex = OPTS_GET(hook, ifindex, 0);
	parent = OPTS_GET(hook, parent, 0);
	attach_point = OPTS_GET(hook, attach_point, 0);

	handle = OPTS_GET(opts, handle, 0);
	priority = OPTS_GET(opts, priority, 0);
	prog_fd = OPTS_GET(opts, prog_fd, 0);
	prog_id = OPTS_GET(opts, prog_id, 0);
	flags = OPTS_GET(opts, flags, 0);

	if (ifindex <= 0 || flags || prog_fd || prog_id)
		return -EINVAL;
	if (priority > UINT16_MAX)
		return -EINVAL;
	if (!flush) {
		if (!handle || !priority)
			return -EINVAL;
		protocol = ETH_P_ALL;
	} else {
		if (handle || priority)
			return -EINVAL;
	}

	memset(&req, 0, sizeof(req));
	req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
	req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nh.nlmsg_type = RTM_DELTFILTER;
	req.t.tcm_family = AF_UNSPEC;
	req.t.tcm_ifindex = ifindex;

	if (!flush) {
		req.t.tcm_handle = handle;
		req.t.tcm_info = TC_H_MAKE(priority << 16, htons(protocol));
	}

	tcm_parent = tc_get_tcm_parent(attach_point, parent);
	if (tcm_parent < 0)
		return tcm_parent;
	req.t.tcm_parent = tcm_parent;

	if (!flush) {
		ret = nlattr_add(&req.nh, sizeof(req), TCA_KIND, "bpf", sizeof("bpf"));
		if (ret < 0)
			return ret;
	}

	return libbpf_nl_send_recv(&req.nh, NULL, NULL, NULL);
}

int bpf_tc_detach(const struct bpf_tc_hook *hook, const struct bpf_tc_opts *opts)
{
	if (!opts)
		return -EINVAL;

	return tc_cls_detach(hook, opts, false);
}

static int __cls_get_info(void *cookie, void *msg, struct nlattr **tb, bool unicast)
{
	struct nlattr *tbb[TCA_BPF_MAX + 1];
	struct pass_info *info = cookie;
	struct tcmsg *t = msg;

	if (!info || !info->opts)
		return -EINVAL;
	if (unicast && info->processed)
		return -EINVAL;
	if (!tb[TCA_OPTIONS])
		return NL_CONT;

	libbpf_nla_parse_nested(tbb, TCA_BPF_MAX, tb[TCA_OPTIONS], NULL);

	if (!tbb[TCA_BPF_ID])
		return -EINVAL;

	OPTS_SET(info->opts, handle, t->tcm_handle);
	OPTS_SET(info->opts, priority, TC_H_MAJ(t->tcm_info) >> 16);
	OPTS_SET(info->opts, prog_id, libbpf_nla_getattr_u32(tbb[TCA_BPF_ID]));

	info->processed = true;
	return unicast ? NL_NEXT : NL_DONE;
}

static int cls_get_info(struct nlmsghdr *nh, libbpf_dump_nlmsg_t fn, void *cookie)
{
	struct tcmsg *t = NLMSG_DATA(nh);
	struct nlattr *tb[TCA_MAX + 1];

	libbpf_nla_parse(tb, TCA_MAX,
			 (struct nlattr *)((char *)t + NLMSG_ALIGN(sizeof(*t))),
			 NLMSG_PAYLOAD(nh, sizeof(*t)), NULL);

	if (!tb[TCA_KIND])
		return NL_CONT;

	return __cls_get_info(cookie, t, tb, nh->nlmsg_flags & NLM_F_ECHO);
}

/* This is the analogue of `tc filter get`, i.e. RTM_GETTFILTER without NLM_F_DUMP */
int bpf_tc_query(const struct bpf_tc_hook *hook, struct bpf_tc_opts *opts)
{
	__u32 protocol, handle, priority, parent, prog_id, flags;
	int ret, ifindex, attach_point, prog_fd;
	struct pass_info pinfo = {};
	long long tcm_parent;
	struct {
		struct nlmsghdr nh;
		struct tcmsg t;
		char buf[256];
	} req;

	if (!hook || !opts || !OPTS_VALID(hook, bpf_tc_hook) || !OPTS_VALID(opts, bpf_tc_opts))
		return -EINVAL;

	ifindex = OPTS_GET(hook, ifindex, 0);
	parent = OPTS_GET(hook, parent, 0);
	attach_point = OPTS_GET(hook, attach_point, 0);

	handle = OPTS_GET(opts, handle, 0);
	priority = OPTS_GET(opts, priority, 0);
	prog_fd = OPTS_GET(opts, prog_fd, 0);
	prog_id = OPTS_GET(opts, prog_id, 0);
	flags = OPTS_GET(opts, flags, 0);

	if (ifindex <= 0 || !handle || !priority || flags || prog_fd || prog_id)
		return -EINVAL;
	if (priority > UINT16_MAX)
		return -EINVAL;

	protocol = ETH_P_ALL;

	memset(&req, 0, sizeof(req));
	req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
	req.nh.nlmsg_flags = NLM_F_REQUEST;
	req.nh.nlmsg_type = RTM_GETTFILTER;
	req.t.tcm_family = AF_UNSPEC;
	req.t.tcm_handle = handle;
	req.t.tcm_ifindex = ifindex;
	req.t.tcm_info = TC_H_MAKE(priority << 16, htons(protocol));

	tcm_parent = tc_get_tcm_parent(attach_point, parent);
	if (tcm_parent < 0)
		return tcm_parent;
	req.t.tcm_parent = tcm_parent;

	ret = nlattr_add(&req.nh, sizeof(req), TCA_KIND, "bpf", sizeof("bpf"));
	if (ret < 0)
		return ret;

	pinfo.opts = opts;

	ret = libbpf_nl_send_recv(&req.nh, &cls_get_info, NULL, &pinfo);
	if (ret < 0)
		return ret;

	if (!pinfo.processed)
		return -ENOENT;

	return ret;
}
