// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2018 Facebook */

#include <stdlib.h>
#include <memory.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <linux/rtnetlink.h>
#include <linux/genetlink.h>
#include <linux/if.h>
#include <sys/socket.h>
#include <errno.h>
#include <time.h>

#include "bpf.h"
#include "libbpf.h"
#include "libbpf_internal.h"
#include "nlattr.h"
#include "ethtool.h"

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

typedef int (*libbpf_dump_nlmsg_t)(void *cookie, void *msg, struct nlattr **tb);

typedef int (*__dump_nlmsg_t)(struct nlmsghdr *nlmsg, libbpf_dump_nlmsg_t,
			      void *cookie);
struct ethnl_msg {
	struct nlmsghdr nlh;
	struct genlmsghdr genlhdr;
	char msg[BUF_SIZE_4096];
};

struct xdp_id_md {
	int ifindex;
	__u32 flags;
	struct xdp_link_info info;
};

static int libbpf_netlink_open(__u32 *nl_pid, int protocol)
{
	struct sockaddr_nl sa;
	socklen_t addrlen;
	int one = 1, ret;
	int sock;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;

	sock = socket(AF_NETLINK, SOCK_RAW, protocol);
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
	struct nlattr *nla, *nla_xdp;
	struct {
		struct nlmsghdr  nh;
		struct ifinfomsg ifinfo;
		char             attrbuf[64];
	} req;
	__u32 nl_pid = 0;

	sock = libbpf_netlink_open(&nl_pid, NETLINK_ROUTE);
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
	nla = (struct nlattr *)(((char *)&req)
				+ NLMSG_ALIGN(req.nh.nlmsg_len));
	nla->nla_type = NLA_F_NESTED | IFLA_XDP;
	nla->nla_len = NLA_HDRLEN;

	/* add XDP fd */
	nla_xdp = (struct nlattr *)((char *)nla + nla->nla_len);
	nla_xdp->nla_type = IFLA_XDP_FD;
	nla_xdp->nla_len = NLA_HDRLEN + sizeof(int);
	memcpy((char *)nla_xdp + NLA_HDRLEN, &fd, sizeof(fd));
	nla->nla_len += nla_xdp->nla_len;

	/* if user passed in any flags, add those too */
	if (flags) {
		nla_xdp = (struct nlattr *)((char *)nla + nla->nla_len);
		nla_xdp->nla_type = IFLA_XDP_FLAGS;
		nla_xdp->nla_len = NLA_HDRLEN + sizeof(flags);
		memcpy((char *)nla_xdp + NLA_HDRLEN, &flags, sizeof(flags));
		nla->nla_len += nla_xdp->nla_len;
	}

	if (flags & XDP_FLAGS_REPLACE) {
		nla_xdp = (struct nlattr *)((char *)nla + nla->nla_len);
		nla_xdp->nla_type = IFLA_XDP_EXPECTED_FD;
		nla_xdp->nla_len = NLA_HDRLEN + sizeof(old_fd);
		memcpy((char *)nla_xdp + NLA_HDRLEN, &old_fd, sizeof(old_fd));
		nla->nla_len += nla_xdp->nla_len;
	}

	req.nh.nlmsg_len += NLA_ALIGN(nla->nla_len);

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

	sock = libbpf_netlink_open(&nl_pid, NETLINK_ROUTE);
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
	int seq = time(NULL);

	req.nlh.nlmsg_seq = seq;
	if (send(sock, &req, req.nlh.nlmsg_len, 0) < 0)
		return -errno;

	return bpf_netlink_recv(sock, nl_pid, seq, __dump_link_nlmsg,
				dump_link_nlmsg, cookie);
}

static int libbpf_ethtool_parse_feature_strings(struct nlattr *start, int elem,
						int *xdp, int *xdp_zc)
{
	struct nlattr *tbs[__ETHTOOL_A_STRING_CNT + 1];
	struct nlattr *tab[elem > 0 ? elem : 0];
	struct libbpf_nla_policy policy[] = {
		[ETHTOOL_A_STRING_UNSPEC] = {
		.type = LIBBPF_NLA_UNSPEC,
		.minlen = 0,
		.maxlen = 0,
		},
		[ETHTOOL_A_STRING_INDEX] = {
		.type = LIBBPF_NLA_U32,
		.minlen = sizeof(uint32_t),
		.maxlen = sizeof(uint32_t),
		},
		[ETHTOOL_A_STRING_VALUE] = {
		.type = LIBBPF_NLA_STRING,
		.minlen = 1,
		.maxlen = ETH_GSTRING_LEN,
		}
	};
	const char *f;
	int n = 0;
	__u32 v;
	int ret;
	int i;

	if (!xdp || !xdp_zc || !start || elem <= 0)
		return -EINVAL;

	*xdp = -1;
	*xdp_zc = -1;

	ret = libbpf_nla_parse_table(tab, elem, start, 0, NULL);
	if (ret)
		goto cleanup;

	for (i = 0; tab[i] && i < elem; ++i) {
		ret = libbpf_nla_parse_nested(tbs, __ETHTOOL_A_STRING_CNT, tab[i], policy);
		if (ret)
			break;

		if (tbs[ETHTOOL_A_STRING_INDEX] && tbs[ETHTOOL_A_STRING_VALUE]) {
			f = libbpf_nla_getattr_str(tbs[ETHTOOL_A_STRING_VALUE]);
			v = libbpf_nla_getattr_u32(tbs[ETHTOOL_A_STRING_INDEX]);

			if (!strncmp(NETDEV_XDP_STR, f, NETDEV_XDP_LEN)) {
				*xdp = v;
				n++;
			}

			if (!strncmp(NETDEV_AF_XDP_ZC_STR, f, NETDEV_AF_XDP_ZC_LEN)) {
				*xdp_zc = v;
				n++;
			}
		} else {
			ret = -LIBBPF_ERRNO__NLPARSE;
			break;
		}
	}

cleanup:
	/* If error occurred return it. */
	if (ret)
		return ret;

	/*
	 * If zero or two xdp flags found that is okay.
	 * Zero means older kernel without any xdp flags added.
	 * Two means newer kernel with xdp flags added.
	 * Both flags were added in single commit, so that
	 * n == 1 is a faulty value.
	 */
	if (n == 2 || n == 0)
		return 0;

	/* If no error and one or more than 2 xdp flags found return error */
	return -LIBBPF_ERRNO__INVXDP;
}

static int libbpf_ethnl_send(int sock, __u32 seq, __u32 nl_pid, struct ethnl_msg *req)
{
	ssize_t written;

	req->nlh.nlmsg_pid = nl_pid;
	req->nlh.nlmsg_seq = seq;

	written = send(sock, req, req->nlh.nlmsg_len, 0);
	if (written < 0)
		return -errno;

	if (written == req->nlh.nlmsg_len)
		return 0;
	else
		return -errno;
}

static int libbpf_ethnl_validate(int len, __u16 fam_id, __u32 nl_pid, __u32 seq,
				 struct ethnl_msg *req)
{
	if (!NLMSG_OK(&req->nlh, (unsigned int)len))
		return -ENOMSG;

	if (req->nlh.nlmsg_pid != nl_pid)
		return -LIBBPF_ERRNO__WRNGPID;

	if (req->nlh.nlmsg_seq != seq)
		return -LIBBPF_ERRNO__INVSEQ;

	if (req->nlh.nlmsg_type != fam_id) {
		int ret = -ENOMSG;

		if (req->nlh.nlmsg_type == NLMSG_ERROR) {
			struct nlmsgerr *err = (struct nlmsgerr *)&req->genlhdr;

			if (err->error)
				ret = err->error;
			libbpf_nla_dump_errormsg(&req->nlh);
		}
		return ret;
	}

	return 0;
}

static int libbpf_ethnl_send_recv(struct ethnl_msg *req, struct ethnl_params *param)
{
	__u32 nl_pid;
	__u32 seq;
	int sock;
	int ret;
	int len;

	sock = libbpf_netlink_open(&nl_pid, NETLINK_GENERIC);
	if (sock < 0) {
		ret = sock;
		goto cleanup;
	}

	seq = time(NULL);
	ret = libbpf_ethnl_send(sock, seq, nl_pid, req);
	if (ret)
		goto cleanup;

	len = recv(sock, req, sizeof(struct ethnl_msg), 0);
	if (len < 0) {
		ret = -errno;
		goto cleanup;
	}

	ret = libbpf_ethnl_validate(len, param->fam_id, nl_pid, seq, req);
	if (ret < 0)
		goto cleanup;

	ret = len;

cleanup:
	if (sock >= 0)
		close(sock);

	return ret;
}

int libbpf_ethnl_get_netdev_features(struct ethnl_params *param)
{
	struct ethnl_msg req = {
		.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct genlmsghdr)),
		.nlh.nlmsg_flags = NLM_F_REQUEST,
		.nlh.nlmsg_type = param->fam_id,
		.nlh.nlmsg_pid = 0,
		.genlhdr.version = ETHTOOL_GENL_VERSION,
		.genlhdr.cmd = ETHTOOL_MSG_STRSET_GET,
		.genlhdr.reserved = 0,
	};
	struct nlattr *tbn[__ETHTOOL_A_STRINGSETS_CNT + 1];
	struct nlattr *tbnn[__ETHTOOL_A_STRINGSET_CNT + 1];
	struct nlattr *tb[__ETHTOOL_A_STRSET_CNT + 1];
	struct nlattr *nla, *nla_next, *nla_set;
	int string_set = ETH_SS_FEATURES;
	int ret;
	int len;

	memset(&req.msg, 0, BUF_SIZE_4096);

	nla = (struct nlattr *)req.msg;
	nla_next = libbpf_nla_nest_start(nla, ETHTOOL_A_STRSET_HEADER);
	nla_next = libbpf_nla_put_str(nla_next, ETHTOOL_A_HEADER_DEV_NAME,
				      param->ifname, IFNAMSIZ);
	libbpf_nla_nest_end(nla, nla_next);

	nla = nla_next;
	nla_set = libbpf_nla_nest_start(nla, ETHTOOL_A_STRSET_STRINGSETS);
	nla_next = libbpf_nla_nest_start(nla_set, ETHTOOL_A_STRINGSETS_STRINGSET);
	nla_next = libbpf_nla_put_u32(nla_next, ETHTOOL_A_STRINGSET_ID, string_set);
	libbpf_nla_nest_end(nla_set, nla_next);
	libbpf_nla_nest_end(nla, nla_next);
	if (!param->features)
		nla_next = libbpf_nla_put_flag(nla_next, ETHTOOL_A_STRSET_COUNTS_ONLY);

	req.nlh.nlmsg_len += libbpf_nla_attrs_length((struct nlattr *)req.msg, nla_next);

	len = libbpf_ethnl_send_recv(&req, param);
	if (len < 0)
		return len;

	/* set parsing error, and change if succeeded */
	ret = -LIBBPF_ERRNO__NLPARSE;
	nla = (struct nlattr *)req.msg;
	len = len - NLMSG_HDRLEN - GENL_HDRLEN;

	if (libbpf_nla_parse(tb, __ETHTOOL_A_STRSET_CNT, nla, len, NULL))
		return ret;

	if (!tb[ETHTOOL_A_STRSET_STRINGSETS])
		return ret;

	if (libbpf_nla_parse_nested(tbn, __ETHTOOL_A_STRINGSETS_CNT,
				    tb[ETHTOOL_A_STRSET_STRINGSETS], NULL))
		return ret;

	if (!tbn[ETHTOOL_A_STRINGSETS_STRINGSET])
		return ret;

	if (libbpf_nla_parse_nested(tbnn, __ETHTOOL_A_STRINGSET_CNT,
				    tbn[ETHTOOL_A_STRINGSETS_STRINGSET], NULL))
		return ret;

	if (param->features == 0) {
		if (!tbnn[ETHTOOL_A_STRINGSET_COUNT])
			return ret;

		param->features = libbpf_nla_getattr_u32(tbnn[ETHTOOL_A_STRINGSET_COUNT]);

		/* success */
		ret = 0;
	} else if (param->features > 0) {
		if (!tbnn[ETHTOOL_A_STRINGSET_STRINGS])
			return ret;

		/*
		 * Upper boundary is known, but it is input from socket stream.
		 * Let's perform upper limit check anyway, and limit it up to
		 * MAX_FEATURES (which is still far more than is actually needed).
		 */
		if (param->features > MAX_FEATURES)
			param->features = MAX_FEATURES;

		/* success if returns 0 */
		ret = libbpf_ethtool_parse_feature_strings(tbnn[ETHTOOL_A_STRINGSET_STRINGS],
							   param->features, &param->xdp_idx,
							   &param->xdp_zc_idx);
	}

	return ret;
}

int libbpf_ethnl_get_ethtool_family_id(struct ethnl_params *param)
{
	struct ethnl_msg req = {
		.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct genlmsghdr)),
		.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
		.nlh.nlmsg_type = GENL_ID_CTRL,
		.nlh.nlmsg_pid = 0,
		.genlhdr.version = ETHTOOL_GENL_VERSION,
		.genlhdr.cmd = CTRL_CMD_GETFAMILY,
		.genlhdr.reserved = 0,
	};
	struct nlattr *tb[__CTRL_ATTR_MAX + 1] = {0};
	struct nlattr *nla, *nla_next;
	int ret = -1;
	int len;

	memset(&req.msg, 0, BUF_SIZE_4096);
	param->fam_id = GENL_ID_CTRL;

	nla = (struct nlattr *)req.msg;
	nla_next = libbpf_nla_put_str(nla, CTRL_ATTR_FAMILY_NAME, param->nl_family, GENL_NAMSIZ);
	req.nlh.nlmsg_len += libbpf_nla_attrs_length(nla, nla_next);

	len = libbpf_ethnl_send_recv(&req, param);
	if (len < 0)
		return len;

	/* set parsing error, and change if succeeded */
	ret = -LIBBPF_ERRNO__NLPARSE;
	len = len - NLMSG_HDRLEN - GENL_HDRLEN;
	if (!libbpf_nla_parse(tb, __CTRL_ATTR_MAX, nla, len, NULL)) {
		if (tb[CTRL_ATTR_FAMILY_ID]) {
			param->fam_id = libbpf_nla_getattr_u16(tb[CTRL_ATTR_FAMILY_ID]);
			ret = 0;
		}
	}

	return ret;
}

int libbpf_ethnl_get_active_bits(struct ethnl_params *param)
{
	struct ethnl_msg req = {
		.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct genlmsghdr)),
		.nlh.nlmsg_flags = NLM_F_REQUEST,
		.nlh.nlmsg_type = param->fam_id,
		.nlh.nlmsg_pid = 0,
		.genlhdr.cmd = ETHTOOL_MSG_FEATURES_GET,
		.genlhdr.version = ETHTOOL_GENL_VERSION,
		.genlhdr.reserved = 0,
	};
	__u32  active[FEATURE_BITS_TO_BLOCKS(param->features)];
	struct nlattr *tb[__ETHTOOL_A_FEATURES_CNT + 1];
	struct nlattr *tbn[__ETHTOOL_A_BITSET_CNT + 1];
	int flags = ETHTOOL_FLAG_COMPACT_BITSETS;
	struct nlattr *nla, *nla_next;
	int ret = -1;
	int len;

	memset(&req.msg, 0, BUF_SIZE_4096);

	nla = (struct nlattr *)req.msg;
	nla_next = libbpf_nla_nest_start(nla, ETHTOOL_A_FEATURES_HEADER);
	nla_next = libbpf_nla_put_str(nla_next, ETHTOOL_A_HEADER_DEV_NAME, param->ifname, IFNAMSIZ);
	nla_next = libbpf_nla_put_u32(nla_next, ETHTOOL_A_HEADER_FLAGS, flags);
	libbpf_nla_nest_end(nla, nla_next);
	req.nlh.nlmsg_len += libbpf_nla_attrs_length(nla, nla_next);

	len = libbpf_ethnl_send_recv(&req, param);
	if (len < 0)
		return len;

	ret = -LIBBPF_ERRNO__NLPARSE;
	nla = (struct nlattr *)req.msg;
	len = len - NLMSG_HDRLEN - GENL_HDRLEN;
	if (libbpf_nla_parse(tb, __ETHTOOL_A_FEATURES_CNT, nla, len, NULL))
		return ret;

	if (!tb[ETHTOOL_A_FEATURES_ACTIVE])
		return ret;

	if (libbpf_nla_parse_nested(tbn, __ETHTOOL_A_BITSET_CNT,
				    tb[ETHTOOL_A_FEATURES_ACTIVE], NULL))
		return ret;

	if (!tbn[ETHTOOL_A_BITSET_VALUE])
		return ret;

	for (unsigned int i = 0; i < FEATURE_BITS_TO_BLOCKS(param->features); ++i)
		active[i]  = libbpf_nla_getattr_u32(tbn[ETHTOOL_A_BITSET_VALUE] + i);

	/* mark successful parsing */
	ret = 0;
	if (FEATURE_BIT_IS_SET(active, param->xdp_idx)) {
		param->xdp_flags = 1;
		if (FEATURE_BIT_IS_SET(active, param->xdp_zc_idx))
			param->xdp_zc_flags = 1;
	} else {
		/* zero copy without driver mode makes no sense */
		if (FEATURE_BIT_IS_SET(active, param->xdp_zc_idx))
			ret = -LIBBPF_ERRNO__INVXDP;
	}

	return ret;
}
