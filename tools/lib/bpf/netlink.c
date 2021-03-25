// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2018 Facebook */

#include <stdlib.h>
#include <memory.h>
#include <unistd.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/atm.h>
#include <linux/pkt_cls.h>
#include <linux/rtnetlink.h>
#include <linux/tc_act/tc_bpf.h>
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
				if (ret)
					return ret;
			}
		}
	}
	ret = 0;
done:
	return ret;
}

static int __bpf_set_link_xdp_fd_replace(int ifindex, int fd, int old_fd,
					 __u32 flags)
{
	int sock, seq = 0, ret;
	struct nlattr *nla;
	struct {
		struct nlmsghdr  nh;
		struct ifinfomsg ifinfo;
		char             attrbuf[64];
	} req;
	__u32 nl_pid = 0;

	sock = libbpf_netlink_open(&nl_pid);
	if (sock < 0)
		return sock;

	memset(&req, 0, sizeof(req));
	req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nh.nlmsg_type = RTM_SETLINK;
	req.nh.nlmsg_pid = 0;
	req.nh.nlmsg_seq = ++seq;
	req.ifinfo.ifi_family = AF_UNSPEC;
	req.ifinfo.ifi_index = ifindex;

	/* started nested attribute for XDP */
	nla = begin_nlattr_nested(&req.nh, sizeof(req), IFLA_XDP);
	if (!nla) {
		ret = -EMSGSIZE;
		goto cleanup;
	}

	/* add XDP fd */
	ret = add_nlattr(&req.nh, sizeof(req), IFLA_XDP_FD, &fd, sizeof(fd));
	if (ret < 0)
		goto cleanup;

	/* if user passed in any flags, add those too */
	if (flags) {
		ret = add_nlattr(&req.nh, sizeof(req), IFLA_XDP_FLAGS, &flags, sizeof(flags));
		if (ret < 0)
			goto cleanup;
	}

	if (flags & XDP_FLAGS_REPLACE) {
		ret = add_nlattr(&req.nh, sizeof(req), IFLA_XDP_EXPECTED_FD, &flags, sizeof(flags));
		if (ret < 0)
			goto cleanup;
	}

	end_nlattr_nested(&req.nh, nla);

	if (send(sock, &req, req.nh.nlmsg_len, 0) < 0) {
		ret = -errno;
		goto cleanup;
	}
	ret = bpf_netlink_recv(sock, nl_pid, seq, NULL, NULL, NULL);

cleanup:
	close(sock);
	return ret;
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

static int libbpf_nl_get_link(int sock, unsigned int nl_pid,
			      libbpf_dump_nlmsg_t dump_link_nlmsg, void *cookie);

int bpf_get_link_xdp_info(int ifindex, struct xdp_link_info *info,
			  size_t info_size, __u32 flags)
{
	struct xdp_id_md xdp_id = {};
	int sock, ret;
	__u32 nl_pid = 0;
	__u32 mask;

	if (flags & ~XDP_FLAGS_MASK || !info_size)
		return -EINVAL;

	/* Check whether the single {HW,DRV,SKB} mode is set */
	flags &= (XDP_FLAGS_SKB_MODE | XDP_FLAGS_DRV_MODE | XDP_FLAGS_HW_MODE);
	mask = flags - 1;
	if (flags && flags & mask)
		return -EINVAL;

	sock = libbpf_netlink_open(&nl_pid);
	if (sock < 0)
		return sock;

	xdp_id.ifindex = ifindex;
	xdp_id.flags = flags;

	ret = libbpf_nl_get_link(sock, nl_pid, get_xdp_info, &xdp_id);
	if (!ret) {
		size_t sz = min(info_size, sizeof(xdp_id.info));

		memcpy(info, &xdp_id.info, sz);
		memset((void *) info + sz, 0, info_size - sz);
	}

	close(sock);
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

static int bpf_nl_get_ext(struct nlmsghdr *nh, int sock, unsigned int nl_pid,
			  __dump_nlmsg_t dump_link_nlmsg_p,
			  libbpf_dump_nlmsg_t dump_link_nlmsg, void *cookie)
{
	int seq = time(NULL);

	nh->nlmsg_seq = seq;
	if (send(sock, nh, nh->nlmsg_len, 0) < 0)
		return -errno;

	return bpf_netlink_recv(sock, nl_pid, seq, dump_link_nlmsg_p,
				dump_link_nlmsg, cookie);
}

int libbpf_nl_get_link(int sock, unsigned int nl_pid,
		       libbpf_dump_nlmsg_t dump_link_nlmsg, void *cookie)
{
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg ifm;
	} req = {
		.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
		.nlh.nlmsg_type = RTM_GETLINK,
		.nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST,
		.ifm.ifi_family = AF_PACKET,
	};

	return bpf_nl_get_ext(&req.nlh, sock, nl_pid, __dump_link_nlmsg,
			      dump_link_nlmsg, cookie);
}

static int tc_bpf_add_fd_and_name(struct nlmsghdr *nh, size_t maxsz, int fd,
				  enum bpf_prog_type type)
{
	int len, ret, bpf_fd_type, bpf_name_type;
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	char name[64] = {};

	switch (type) {
	case BPF_PROG_TYPE_SCHED_CLS:
		bpf_fd_type = TCA_BPF_FD;
		bpf_name_type = TCA_BPF_NAME;
		break;
	case BPF_PROG_TYPE_SCHED_ACT:
		bpf_fd_type = TCA_ACT_BPF_FD;
		bpf_name_type = TCA_ACT_BPF_NAME;
		break;
	default:
		return -EINVAL;
	}

	ret = bpf_obj_get_info_by_fd(fd, &info, &info_len);
	if (ret < 0 || type != info.type)
		return ret;

	ret = add_nlattr(nh, maxsz, bpf_fd_type, &fd, sizeof(fd));
	if (ret < 0)
		return ret;

	len = snprintf(name, sizeof(name), "%s:[%" PRIu32 "]", info.name,
		       info.id);
	if (len < 0 || len >= sizeof(name))
		return len < 0 ? -EINVAL : -ENAMETOOLONG;

	return add_nlattr(nh, maxsz, bpf_name_type, name, len + 1);
}

struct pass_info {
	void *info;
	__u32 prog_id;
};

static int cls_get_info(struct nlmsghdr *nh, libbpf_dump_nlmsg_t fn,
			void *cookie);

static int tc_cls_bpf_modify(int fd, int cmd, unsigned int flags, __u32 ifindex,
			     __u32 parent_id, __u32 protocol,
			     const struct bpf_tc_cls_opts *opts,
			     __dump_nlmsg_t fn, struct bpf_tc_cls_attach_id *id)
{
	unsigned int bpf_flags = 0, bpf_flags_gen = 0;
	struct bpf_tc_cls_info info = {};
	int sock, seq = 0, ret;
	struct nlattr *nla;
	__u32 nl_pid = 0;
	struct {
		struct nlmsghdr nh;
		struct tcmsg t;
		char buf[256];
	} req;

	if (OPTS_GET(opts, priority, 0) > 0xFFFF)
		return -EINVAL;

	sock = libbpf_netlink_open(&nl_pid);
	if (sock < 0)
		return sock;

	memset(&req, 0, sizeof(req));
	req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
	req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | flags;
	req.nh.nlmsg_type = cmd;
	req.nh.nlmsg_pid = 0;
	req.nh.nlmsg_seq = ++seq;
	req.t.tcm_family = AF_UNSPEC;
	req.t.tcm_handle = OPTS_GET(opts, handle, 0);
	req.t.tcm_parent = parent_id;
	req.t.tcm_ifindex = ifindex;
	req.t.tcm_info =
		TC_H_MAKE(OPTS_GET(opts, priority, 0UL) << 16, htons(protocol));

	if (OPTS_HAS(opts, chain_index)) {
		ret = add_nlattr(&req.nh, sizeof(req), TCA_CHAIN,
				 &opts->chain_index, sizeof(opts->chain_index));
		if (ret < 0)
			goto end;
	}

	ret = add_nlattr(&req.nh, sizeof(req), TCA_KIND, "bpf", sizeof("bpf"));
	if (ret < 0)
		goto end;

	nla = begin_nlattr_nested(&req.nh, sizeof(req), TCA_OPTIONS);
	if (!nla) {
		ret = -EMSGSIZE;
		goto end;
	}

	if (OPTS_GET(opts, class_id, TC_H_UNSPEC)) {
		ret = add_nlattr(&req.nh, sizeof(req), TCA_BPF_CLASSID,
				 &opts->class_id, sizeof(opts->class_id));
		if (ret < 0)
			goto end;
	}

	if (cmd != RTM_DELTFILTER) {
		ret = tc_bpf_add_fd_and_name(&req.nh, sizeof(req), fd,
					     BPF_PROG_TYPE_SCHED_CLS);
		if (ret < 0)
			goto end;

		if (OPTS_GET(opts, skip_hw, false))
			bpf_flags_gen |= TCA_CLS_FLAGS_SKIP_HW;
		if (OPTS_GET(opts, skip_sw, false))
			bpf_flags_gen |= TCA_CLS_FLAGS_SKIP_SW;
		if (OPTS_GET(opts, direct_action, false))
			bpf_flags |= TCA_BPF_FLAG_ACT_DIRECT;

		if (bpf_flags_gen) {
			ret = add_nlattr(&req.nh, sizeof(req),
					 TCA_BPF_FLAGS_GEN, &bpf_flags_gen,
					 sizeof(bpf_flags_gen));
			if (ret < 0)
				goto end;
		}

		if (bpf_flags) {
			ret = add_nlattr(&req.nh, sizeof(req), TCA_BPF_FLAGS,
					 &bpf_flags, sizeof(bpf_flags));
			if (ret < 0)
				goto end;
		}
	}

	end_nlattr_nested(&req.nh, nla);

	ret = send(sock, &req.nh, req.nh.nlmsg_len, 0);
	if (ret < 0)
		goto end;

	ret = bpf_netlink_recv(sock, nl_pid, seq, fn, NULL,
			       &(struct pass_info){ &info, 0 });

	if (fn)
		*id = info.id;

end:
	close(sock);
	return ret;
}

int bpf_tc_cls_attach_dev(int fd, __u32 ifindex, __u32 parent_id,
			  __u32 protocol, const struct bpf_tc_cls_opts *opts,
			  struct bpf_tc_cls_attach_id *id)
{
	if (fd < 1 || !OPTS_VALID(opts, bpf_tc_cls_opts) || !id)
		return -EINVAL;

	return tc_cls_bpf_modify(fd, RTM_NEWTFILTER,
				 NLM_F_ECHO | NLM_F_EXCL | NLM_F_CREATE,
				 ifindex, parent_id, protocol, opts,
				 cls_get_info, id);
}

int bpf_tc_cls_change_dev(int fd, __u32 ifindex, __u32 parent_id,
			  __u32 protocol, const struct bpf_tc_cls_opts *opts,
			  struct bpf_tc_cls_attach_id *id)
{
	if (fd < 1 || !OPTS_VALID(opts, bpf_tc_cls_opts) || !id)
		return -EINVAL;

	return tc_cls_bpf_modify(fd, RTM_NEWTFILTER, NLM_F_ECHO, ifindex,
				 parent_id, protocol, opts, cls_get_info, id);
}

int bpf_tc_cls_replace_dev(int fd, __u32 ifindex, __u32 parent_id,
			   __u32 protocol, const struct bpf_tc_cls_opts *opts,
			   struct bpf_tc_cls_attach_id *id)
{
	if (fd < 1 || !OPTS_VALID(opts, bpf_tc_cls_opts) || !id)
		return -EINVAL;

	return tc_cls_bpf_modify(fd, RTM_NEWTFILTER, NLM_F_ECHO | NLM_F_CREATE,
				 ifindex, parent_id, protocol, opts,
				 cls_get_info, id);
}

int bpf_tc_cls_detach_dev(const struct bpf_tc_cls_attach_id *id)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_cls_opts, opts, 0);

	if (!id)
		return -EINVAL;

	opts.chain_index = id->chain_index;
	opts.handle = id->handle;
	opts.priority = id->priority;

	return tc_cls_bpf_modify(-1, RTM_DELTFILTER, 0, id->ifindex,
				 id->parent_id, id->protocol, &opts, NULL,
				 NULL);
}

int bpf_tc_cls_attach_block(int fd, __u32 block_index, __u32 protocol,
			    const struct bpf_tc_cls_opts *opts,
			    struct bpf_tc_cls_attach_id *id)
{
	return bpf_tc_cls_attach_dev(fd, TCM_IFINDEX_MAGIC_BLOCK, block_index,
				     protocol, opts, id);
}

int bpf_tc_cls_change_block(int fd, __u32 block_index, __u32 protocol,
			    const struct bpf_tc_cls_opts *opts,
			    struct bpf_tc_cls_attach_id *id)
{
	return bpf_tc_cls_attach_dev(fd, TCM_IFINDEX_MAGIC_BLOCK, block_index,
				     protocol, opts, id);
}

int bpf_tc_cls_replace_block(int fd, __u32 block_index, __u32 protocol,
			     const struct bpf_tc_cls_opts *opts,
			     struct bpf_tc_cls_attach_id *id)
{
	return bpf_tc_cls_attach_dev(fd, TCM_IFINDEX_MAGIC_BLOCK, block_index,
				     protocol, opts, id);
}

int bpf_tc_cls_detach_block(const struct bpf_tc_cls_attach_id *id)
{
	return bpf_tc_cls_detach_dev(id);
}

static int __cls_get_info(void *cookie, void *msg, struct nlattr **tb)
{
	struct nlattr *tbb[TCA_BPF_MAX + 1];
	struct pass_info *cinfo = cookie;
	struct bpf_tc_cls_info *info;
	struct tcmsg *t = msg;
	__u32 prog_id;

	info = cinfo->info;

	if (!tb[TCA_OPTIONS])
		return 0;

	libbpf_nla_parse_nested(tbb, TCA_BPF_MAX, tb[TCA_OPTIONS], NULL);
	if (!tbb[TCA_BPF_ID])
		return 0;

	prog_id = libbpf_nla_getattr_u32(tbb[TCA_BPF_ID]);
	if (cinfo->prog_id && cinfo->prog_id != prog_id)
		return 0;

	info->id.parent_id = t->tcm_parent;
	info->id.ifindex = t->tcm_ifindex;
	info->id.protocol = ntohs(TC_H_MIN(t->tcm_info));
	info->id.priority = TC_H_MAJ(t->tcm_info) >> 16;
	info->id.handle = t->tcm_handle;

	if (tb[TCA_CHAIN])
		info->id.chain_index = libbpf_nla_getattr_u32(tb[TCA_CHAIN]);
	else
		info->id.chain_index = 0;

	if (tbb[TCA_BPF_FLAGS])
		info->bpf_flags = libbpf_nla_getattr_u32(tbb[TCA_BPF_FLAGS]);

	if (tbb[TCA_BPF_FLAGS_GEN])
		info->bpf_flags_gen =
			libbpf_nla_getattr_u32(tbb[TCA_BPF_FLAGS_GEN]);

	if (tbb[TCA_BPF_CLASSID])
		info->class_id = libbpf_nla_getattr_u32(tbb[TCA_BPF_CLASSID]);

	return 1;
}

static int cls_get_info(struct nlmsghdr *nh, libbpf_dump_nlmsg_t fn,
			void *cookie)
{
	struct tcmsg *t = NLMSG_DATA(nh);
	struct nlattr *tb[TCA_MAX + 1];

	libbpf_nla_parse(tb, TCA_MAX,
			 (struct nlattr *)((char *)t + NLMSG_ALIGN(sizeof(*t))),
			 NLMSG_PAYLOAD(nh, sizeof(*t)), NULL);
	if (!tb[TCA_KIND])
		return -EINVAL;

	return __cls_get_info(cookie, t, tb);
}

static int tc_cls_get_info(int fd, __u32 ifindex, __u32 parent_id,
			   __u32 protocol, const struct bpf_tc_cls_opts *opts,
			   struct bpf_tc_cls_info *info)
{
	__u32 nl_pid, info_len = sizeof(struct bpf_prog_info);
	struct bpf_prog_info prog_info = {};
	int sock, ret;
	struct {
		struct nlmsghdr nh;
		struct tcmsg t;
		char buf[256];
	} req = {
		.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg)),
		.nh.nlmsg_type = RTM_GETTFILTER,
		.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
		.t.tcm_family = AF_UNSPEC,
	};

	if (!OPTS_VALID(opts, bpf_tc_cls_opts))
		return -EINVAL;

	req.t.tcm_parent = parent_id;
	req.t.tcm_ifindex = ifindex;
	req.t.tcm_handle = OPTS_GET(opts, handle, 0);
	req.t.tcm_info =
		TC_H_MAKE(OPTS_GET(opts, priority, 0UL) << 16, htons(protocol));

	ret = bpf_obj_get_info_by_fd(fd, &prog_info, &info_len);
	if (ret < 0)
		return ret;

	sock = libbpf_netlink_open(&nl_pid);
	if (sock < 0)
		return sock;

	ret = add_nlattr(&req.nh, sizeof(req), TCA_KIND, "bpf", sizeof("bpf"));
	if (ret < 0)
		goto end;

	if (OPTS_HAS(opts, chain_index)) {
		ret = add_nlattr(&req.nh, sizeof(req), TCA_CHAIN,
				 &opts->chain_index, sizeof(opts->chain_index));
		if (ret < 0)
			goto end;
	}

	req.nh.nlmsg_seq = time(NULL);

	ret = bpf_nl_get_ext(&req.nh, sock, nl_pid, cls_get_info, NULL,
			     &(struct pass_info){ info, prog_info.id });
	if (ret < 0)
		goto end;
	/* 1 denotes a match */
	ret = ret == 1 ? 0 : -ESRCH;
end:
	close(sock);
	return ret;
}

int bpf_tc_cls_get_info_dev(int fd, __u32 ifindex, __u32 parent_id,
			    __u32 protocol, const struct bpf_tc_cls_opts *opts,
			    struct bpf_tc_cls_info *info)
{
	return tc_cls_get_info(fd, ifindex, parent_id, protocol, opts, info);
}

int bpf_tc_cls_get_info_block(int fd, __u32 block_index, __u32 protocol,
			      const struct bpf_tc_cls_opts *opts,
			      struct bpf_tc_cls_info *info)
{
	return bpf_tc_cls_get_info_dev(fd, TCM_IFINDEX_MAGIC_BLOCK, block_index,
				       protocol, opts, info);
}

static int tc_act_add_action(struct nlmsghdr *nh, size_t maxsz, int type,
			     int fd, const struct bpf_tc_act_opts *opts)
{
	struct nlattr *nla, *nla_opt, *nla_subopt;
	struct tc_act_bpf param = {};
	int ret;

	nla = begin_nlattr_nested(nh, maxsz, type);
	if (!nla)
		return -EMSGSIZE;

	nla_opt = begin_nlattr_nested(nh, maxsz, 1);
	if (!nla_opt)
		return -EMSGSIZE;

	ret = add_nlattr(nh, maxsz, TCA_ACT_KIND, "bpf", sizeof("bpf"));
	if (ret < 0)
		return ret;

	ret = add_nlattr(nh, maxsz, TCA_ACT_INDEX,
			 OPTS_HAS(opts, index) ? &opts->index : &(__u32){ 0 },
			 sizeof(opts->index));

	if (ret < 0)
		return ret;

	nla_subopt = begin_nlattr_nested(nh, maxsz, TCA_ACT_OPTIONS);
	if (!nla)
		return -EMSGSIZE;

	if (fd > 0) {
		ret = tc_bpf_add_fd_and_name(nh, maxsz, fd,
					     BPF_PROG_TYPE_SCHED_ACT);
		if (ret < 0)
			return ret;
	}

	param.index = OPTS_GET(opts, index, 0);
	param.action = OPTS_GET(opts, action, TC_ACT_UNSPEC);

	ret = add_nlattr(nh, maxsz, TCA_ACT_BPF_PARMS, &param, sizeof(param));
	if (ret < 0)
		return ret;

	if (OPTS_GET(opts, cookie, NULL) && OPTS_GET(opts, cookie_len, 0)) {
		if (opts->cookie_len > TC_COOKIE_MAX_SIZE)
			return -E2BIG;

		ret = add_nlattr(nh, maxsz, TCA_ACT_COOKIE, opts->cookie,
				 opts->cookie_len);
		if (ret < 0)
			return ret;
	}

	if (OPTS_GET(opts, hw_stats_type, 0)) {
		struct nla_bitfield32 hw_stats_bf = {
			.value = opts->hw_stats_type,
			.selector = opts->hw_stats_type,
		};

		ret = add_nlattr(nh, maxsz, TCA_ACT_HW_STATS, &hw_stats_bf,
				 sizeof(hw_stats_bf));
		if (ret < 0)
			return ret;
	}

	if (OPTS_GET(opts, no_percpu, false)) {
		struct nla_bitfield32 flags = {
			TCA_ACT_FLAGS_NO_PERCPU_STATS,
			TCA_ACT_FLAGS_NO_PERCPU_STATS,
		};

		ret = add_nlattr(nh, maxsz, TCA_ACT_FLAGS, &flags,
				 sizeof(flags));
		if (ret < 0)
			return ret;
	}

	end_nlattr_nested(nh, nla_subopt);
	end_nlattr_nested(nh, nla_opt);
	end_nlattr_nested(nh, nla);

	return 0;
}

static int tc_act_modify(int cmd, unsigned int flags, int fd, int action,
			 const struct bpf_tc_act_opts *opts, __dump_nlmsg_t fn,
			 __u32 *index)
{
	struct bpf_tc_act_info info = {};
	int sock, seq = 0, ret;
	__u32 nl_pid = 0;
	struct {
		struct nlmsghdr nh;
		struct tcamsg t;
		char buf[256];
	} req;

	sock = libbpf_netlink_open(&nl_pid);
	if (sock < 0)
		return sock;

	memset(&req, 0, sizeof(req));
	req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcamsg));
	req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | flags;
	req.nh.nlmsg_type = cmd;
	req.nh.nlmsg_pid = 0;
	req.nh.nlmsg_seq = ++seq;
	req.t.tca_family = AF_UNSPEC;

	/* gcc complains when using req.nh here */
	ret = tc_act_add_action((struct nlmsghdr *)&req, sizeof(req),
				TCA_ACT_TAB, fd, opts);
	if (ret < 0)
		goto end;

	ret = send(sock, &req.nh, req.nh.nlmsg_len, 0);
	if (ret < 0)
		goto end;

	ret = bpf_netlink_recv(sock, nl_pid, seq, fn, NULL,
			       &(struct pass_info){ &info, 0 });
	if (ret < 0)
		goto end;

	if (fn) {
		if (info.index) {
			*index = info.index;
			ret = 0;
		} else
			ret = -ESRCH;
	}

end:
	close(sock);
	return ret;
}

static int get_act_info(struct nlmsghdr *nh, libbpf_dump_nlmsg_t fn,
			void *cookie);

int bpf_tc_act_attach(int fd, const struct bpf_tc_act_opts *opts, __u32 *index)
{
	if (fd < 1 || !OPTS_VALID(opts, bpf_tc_act_opts) || !index)
		return -EINVAL;

	return tc_act_modify(RTM_NEWACTION, NLM_F_ECHO | NLM_F_EXCL, fd,
			     OPTS_GET(opts, action, TCA_ACT_UNSPEC), opts,
			     get_act_info, index);
}

int bpf_tc_act_replace(int fd, const struct bpf_tc_act_opts *opts, __u32 *index)
{
	if (fd < 1 || !OPTS_VALID(opts, bpf_tc_act_opts) || !index)
		return -EINVAL;

	return tc_act_modify(RTM_NEWACTION, NLM_F_ECHO | NLM_F_REPLACE, fd,
			     OPTS_GET(opts, action, TCA_ACT_UNSPEC), opts,
			     get_act_info, index);
}

int bpf_tc_act_detach(__u32 index)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_act_opts, opts, .index = index);

	return tc_act_modify(RTM_DELACTION, index ? 0 : NLM_F_ROOT, -1,
			     TC_ACT_UNSPEC, &opts, NULL, NULL);
}

static int __get_act_info(void *cookie, void *msg, struct nlattr *nla)
{
	struct nlattr *tbb[TCA_ACT_BPF_MAX + 1];
	struct pass_info *ainfo = cookie;
	struct bpf_tc_act_info *info;
	struct tc_act_bpf parm;
	__u32 prog_id;

	info = ainfo->info;

	if (!nla)
		return -EINVAL;

	libbpf_nla_parse_nested(tbb, TCA_ACT_BPF_MAX, nla, NULL);

	if (!tbb[TCA_ACT_BPF_PARMS] || !tbb[TCA_ACT_BPF_ID])
		return -ESRCH;

	prog_id = libbpf_nla_getattr_u32(tbb[TCA_ACT_BPF_ID]);
	if (ainfo->prog_id && ainfo->prog_id != prog_id)
		return 0;

	/* Found a match */
	memcpy(&parm, libbpf_nla_data(tbb[TCA_ACT_BPF_PARMS]),
	       sizeof(parm));

	info->index = parm.index;
	info->capab = parm.capab;
	info->action = parm.action;
	info->refcnt = parm.refcnt;
	info->bindcnt = parm.bindcnt;

	return 1;
}

static int get_act_info_msg(struct nlmsghdr *nh, libbpf_dump_nlmsg_t fn,
			    void *cookie, __u32 total, struct nlattr *nla)
{
	struct nlattr *tbb[TCA_ACT_MAX + 1];
	struct tcamsg *t = NLMSG_DATA(nh);
	struct nlattr *tb[total + 1];
	int ret;

	libbpf_nla_parse_nested(tb, total, nla, NULL);

	for (int i = 0; i <= total; i++) {
		if (tb[i]) {
			nla = tb[i];
			libbpf_nla_parse_nested(tbb, TCA_ACT_MAX, nla, NULL);

			if (!tbb[TCA_ACT_KIND])
				return -EINVAL;

			ret = __get_act_info(cookie, t, tbb[TCA_ACT_OPTIONS]);
			if (ret < 0)
				return ret;

			if (ret > 0)
				return 1;
		}
	}

	return 0;
}

static int get_act_info(struct nlmsghdr *nh, libbpf_dump_nlmsg_t fn,
			void *cookie)
{
	struct nlattr *nla, *tb[TCA_ROOT_MAX + 1];
	__u32 total = 0;

	nla = NLMSG_DATA(nh) + NLMSG_ALIGN(sizeof(struct tcamsg));
	libbpf_nla_parse(tb, TCA_ROOT_MAX, nla,
			 NLMSG_PAYLOAD(nh, sizeof(struct tcamsg)), NULL);

	if (tb[TCA_ROOT_COUNT])
		total = libbpf_nla_getattr_u32(tb[TCA_ROOT_COUNT]);

	total = total ?: TCA_ACT_MAX_PRIO;

	return get_act_info_msg(nh, fn, cookie, total, tb[TCA_ACT_TAB]);
}

static int tc_act_get_info(int sock, unsigned int nl_pid, int fd,
			   struct bpf_tc_act_info *info)
{
	struct bpf_prog_info prog_info = {};
	__u32 info_len = sizeof(prog_info);
	struct nlattr *nla, *nla_opt;
	struct {
		struct nlmsghdr nh;
		struct tcamsg t;
		char buf[256];
	} req = {
		.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcamsg)),
		.nh.nlmsg_type = RTM_GETACTION,
		.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
		.t.tca_family = AF_UNSPEC,
	};
	int ret;

	if (fd < 1)
		return -EINVAL;

	ret = bpf_obj_get_info_by_fd(fd, &prog_info, &info_len);
	if (ret < 0)
		return ret;

	nla = begin_nlattr_nested(&req.nh, sizeof(req), TCA_ACT_TAB);
	if (!nla)
		return -EMSGSIZE;

	nla_opt = begin_nlattr_nested(&req.nh, sizeof(req), 1);
	if (!nla_opt)
		return -EMSGSIZE;

	ret = add_nlattr(&req.nh, sizeof(req), TCA_ACT_KIND, "bpf",
			 sizeof("bpf"));
	if (ret < 0)
		return ret;

	end_nlattr_nested(&req.nh, nla_opt);
	end_nlattr_nested(&req.nh, nla);

	req.nh.nlmsg_seq = time(NULL);

	/* Pass prog id the info is to be returned for */
	return bpf_nl_get_ext(&req.nh, sock, nl_pid, get_act_info, NULL,
			      &(struct pass_info){ info, prog_info.id });
}

int bpf_tc_act_get_info(int fd, struct bpf_tc_act_info *info)
{
	int sock, ret;
	__u32 nl_pid;

	if (fd < 1 || !info)
		return -EINVAL;

	sock = libbpf_netlink_open(&nl_pid);
	if (sock < 0)
		return sock;

	ret = tc_act_get_info(sock, nl_pid, fd, info);
	if (ret < 0)
		goto end;

	if (!info->index)
		ret = -ESRCH;
end:
	close(sock);
	return ret;
}
