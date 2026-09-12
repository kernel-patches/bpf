// SPDX-License-Identifier: GPL-2.0
/*
 * libmnl helper to set/query the per-service secure_tcp flag
 * (IP_VS_SVC_F_SECURE_TCP), which ipvsadm does not expose.
 *
 * Usage:
 *   ipvs_secure_tcp_mln add <vip> <port> <secure|plain>
 *       Create a TCP virtual service (scheduler "rr") with the flag either
 *       set or not.  Add real servers afterwards with:
 *           ipvsadm -a -t <vip>:<port> -r <rs>:<port>
 *   ipvs_secure_tcp_mln get <vip> <port>
 *       Print "secure_tcp=<0|1>" for the service.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/ip_vs.h>

#include <libmnl/libmnl.h>

/* Fallback in case the kernel's installed uapi header is older */
#ifndef IP_VS_SVC_F_SECURE_TCP
#define IP_VS_SVC_F_SECURE_TCP	0x0040
#endif

/* 16-byte address storage, matching union nf_inet_addr for AF_INET */
struct inet_addr16 {
	uint8_t all[16];
};

/* ---------------- family resolver ---------------- */
static int ctrl_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, CTRL_ATTR_MAX) < 0)
		return MNL_CB_ERROR;
	if (type == CTRL_ATTR_FAMILY_ID) {
		if (mnl_attr_validate(attr, MNL_TYPE_U16) < 0)
			return MNL_CB_ERROR;
		tb[CTRL_ATTR_FAMILY_ID] = attr;
	}
	return MNL_CB_OK;
}

static int ctrl_data_cb(const struct nlmsghdr *nlh, void *data)
{
	const struct nlattr *tb[CTRL_ATTR_MAX + 1] = { 0 };
	uint16_t *fam = data;

	if (nlh->nlmsg_type != GENL_ID_CTRL)
		return MNL_CB_OK;
	mnl_attr_parse(nlh, sizeof(struct genlmsghdr),
		       (mnl_attr_cb_t)ctrl_attr_cb, tb);
	if (tb[CTRL_ATTR_FAMILY_ID]) {
		*fam = mnl_attr_get_u16(tb[CTRL_ATTR_FAMILY_ID]);
		return MNL_CB_STOP;
	}
	return MNL_CB_OK;
}

static int resolve_family(const char *name, uint16_t *fam)
{
	struct mnl_socket *nl;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct genlmsghdr *genl;
	int ret;

	nl = mnl_socket_open(NETLINK_GENERIC);
	if (!nl)
		return -errno;
	mnl_socket_bind(nl, 0, 0);

	nlh = mnl_nlmsg_put_header(buf);
	genl = mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr));
	genl->cmd = CTRL_CMD_GETFAMILY;
	genl->version = 1;
	nlh->nlmsg_type = GENL_ID_CTRL;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	mnl_attr_put_strz(nlh, CTRL_ATTR_FAMILY_NAME, name);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		mnl_socket_close(nl);
		return -errno;
	}
	do {
		ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
		if (ret < 0) {
			if (errno == EAGAIN)
				continue;
			mnl_socket_close(nl);
			return -errno;
		}
		ret = mnl_cb_run(buf, ret, 0, mnl_socket_get_portid(nl),
				 (mnl_cb_t)ctrl_data_cb, fam);
	} while (ret > 0 && *fam == 0);

	mnl_socket_close(nl);
	return *fam ? 0 : -ENOENT;
}

/* ---------------- fill service identifying attrs ---------------- */
static int fill_service(struct nlmsghdr *nlh, const char *vip,
			uint16_t port, int full, int secure)
{
	struct inet_addr16 vaddr = { 0 };
	struct nlattr *nest;
	struct ip_vs_flags fl;
	int af = AF_INET;

	if (inet_pton(af, vip, vaddr.all) != 1) {
		fprintf(stderr, "bad VIP %s\n", vip);
		return -EINVAL;
	}

	nest = mnl_attr_nest_start(nlh, IPVS_CMD_ATTR_SERVICE);
	mnl_attr_put_u16(nlh, IPVS_SVC_ATTR_AF, af);
	mnl_attr_put_u16(nlh, IPVS_SVC_ATTR_PROTOCOL, IPPROTO_TCP);
	mnl_attr_put(nlh, IPVS_SVC_ATTR_ADDR, sizeof(vaddr), &vaddr);
	/* port/be16: port is passed in network order from main() */
	mnl_attr_put_u16(nlh, IPVS_SVC_ATTR_PORT, port);

	if (full) {
		mnl_attr_put_strz(nlh, IPVS_SVC_ATTR_SCHED_NAME, "rr");
		memset(&fl, 0, sizeof(fl));
		fl.mask = IP_VS_SVC_F_SECURE_TCP;
		if (secure)
			fl.flags = IP_VS_SVC_F_SECURE_TCP;
		mnl_attr_put(nlh, IPVS_SVC_ATTR_FLAGS, sizeof(fl), &fl);
		mnl_attr_put_u32(nlh, IPVS_SVC_ATTR_TIMEOUT, 0);
		mnl_attr_put_u32(nlh, IPVS_SVC_ATTR_NETMASK, 0xffffffff);
	}
	mnl_attr_nest_end(nlh, nest);
	return 0;
}

static int send_cmd(struct mnl_socket *nl, struct nlmsghdr *nlh)
{
	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		perror("sendto");
		return -1;
	}
	return 0;
}

/* ---------------- get secure flag ---------------- */
static int svc_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, IPVS_SVC_ATTR_MAX) < 0)
		return MNL_CB_ERROR;
	tb[type] = attr;
	return MNL_CB_OK;
}

static int get_cb(const struct nlmsghdr *nlh, void *data)
{
	const struct nlattr *tb[IPVS_SVC_ATTR_MAX + 1] = { 0 };
	struct ip_vs_flags fl;
	int *secure = data;
	struct nlattr *nest;

	mnl_attr_for_each(nest, nlh, sizeof(struct genlmsghdr)) {
		if (mnl_attr_get_type(nest) == IPVS_CMD_ATTR_SERVICE)
			mnl_attr_parse_nested(nest, (mnl_attr_cb_t)svc_attr_cb, tb);
	}
	if (tb[IPVS_SVC_ATTR_FLAGS]) {
		memcpy(&fl, mnl_attr_get_payload(tb[IPVS_SVC_ATTR_FLAGS]),
		       sizeof(fl));
		*secure = !!(fl.flags & IP_VS_SVC_F_SECURE_TCP);
	}
	return MNL_CB_STOP;
}

static int do_get(uint16_t fam, const char *vip, uint16_t port)
{
	struct mnl_socket *nl;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct genlmsghdr *genl;
	int ret, secure = -1;

	nl = mnl_socket_open(NETLINK_GENERIC);
	mnl_socket_bind(nl, 0, 0);
	nlh = mnl_nlmsg_put_header(buf);
	genl = mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr));
	genl->cmd = IPVS_CMD_GET_SERVICE;
	genl->version = IPVS_GENL_VERSION;
	nlh->nlmsg_type = fam;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	fill_service(nlh, vip, port, 0, 0);
	send_cmd(nl, nlh);

	ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	while (ret >= 0) {
		ret = mnl_cb_run(buf, ret, 0, mnl_socket_get_portid(nl),
				 (mnl_cb_t)get_cb, &secure);
		if (ret <= MNL_CB_STOP || secure >= 0)
			break;
		ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	}
	mnl_socket_close(nl);
	if (secure < 0)
		return -ENOENT;
	printf("secure_tcp=%d\n", secure);
	return 0;
}

/* ---------------- add service with flag ---------------- */
static int do_add(uint16_t fam, const char *vip, uint16_t port, int secure)
{
	struct mnl_socket *nl;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct genlmsghdr *genl;
	int ret;

	/* NLM_F_EXCL: fail if the service already exists */
	nlh = mnl_nlmsg_put_header(buf);
	genl = mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr));
	genl->cmd = IPVS_CMD_NEW_SERVICE;
	genl->version = IPVS_GENL_VERSION;
	nlh->nlmsg_type = fam;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
	fill_service(nlh, vip, port, 1, secure);

	nl = mnl_socket_open(NETLINK_GENERIC);
	mnl_socket_bind(nl, 0, 0);
	if (send_cmd(nl, nlh) < 0) {
		mnl_socket_close(nl);
		return 1;
	}

	/* Read the reply so we can report why a command may have failed */
	for (;;) {
		ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
		if (ret <= 0)
			break;
		ret = mnl_cb_run(buf, ret, 0, mnl_socket_get_portid(nl),
				 NULL, NULL);
		if (ret < 0) {
			int e = errno;

			fprintf(stderr, "IPVS netlink error: ret=%d errno=%d (%s)\n",
				ret, e, strerror(e));
			mnl_socket_close(nl);
			return 1;
		}
		if (ret <= MNL_CB_STOP)
			break;
	}
	mnl_socket_close(nl);
	return 0;
}

int main(int argc, char *argv[])
{
	const char *cmd, *vip;
	uint16_t fam;
	uint16_t port;
	int ret, secure = 0;

	if (argc < 4) {
		fprintf(stderr,
			"usage: %s add <vip> <port> <secure|plain>\n"
			"       %s get <vip> <port>\n", argv[0], argv[0]);
		return 2;
	}
	cmd = argv[1];
	vip = argv[2];
	port = (uint16_t)atoi(argv[3]);
	port = htons(port);

	ret = resolve_family(IPVS_GENL_NAME, &fam);
	if (ret) {
		fprintf(stderr, "cannot resolve IPVS genl family: %s\n",
			strerror(-ret));
		return 1;
	}

	if (strcmp(cmd, "add") == 0) {
		if (argc < 5) {
			fprintf(stderr, "usage: %s add ... <secure|plain>\n",
				argv[0]);
			return 2;
		}
		if (strcmp(argv[4], "secure") == 0) {
			secure = 1;
		} else if (strcmp(argv[4], "plain") != 0) {
			fprintf(stderr, "unknown mode %s\n", argv[4]);
			return 2;
		}
		return do_add(fam, vip, port, secure);
	} else if (strcmp(cmd, "get") == 0) {
		return do_get(fam, vip, port);
	}

	fprintf(stderr, "unknown command %s\n", cmd);
	return 2;
}
