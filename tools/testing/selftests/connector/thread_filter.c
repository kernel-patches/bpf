// SPDX-License-Identifier: GPL-2.0-only
/*
 * Author: Anjali Kulkarni <anjali.k.kulkarni@oracle.com>
 *
 * Copyright (c) 2024 Oracle and/or its affiliates.
 */

#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <errno.h>
#include <signal.h>
#include <string.h>

#define NL_MESSAGE_SIZE (sizeof(struct nlmsghdr) + sizeof(struct cn_msg) + \
			sizeof(struct proc_input))

/*
 * Send PROC_CN_MCAST_NOTIFY type notification to the connector code in kernel.
 * This will send the exit_code specified by user to the connector layer, so
 * it can send a notification for that event to any listening process
 */
int send_message(int nl_sock, unsigned int exit_code)
{
	char buff[NL_MESSAGE_SIZE];
	struct nlmsghdr *hdr;
	struct cn_msg *msg;

	hdr = (struct nlmsghdr *)buff;
	hdr->nlmsg_len = NL_MESSAGE_SIZE;
	hdr->nlmsg_type = NLMSG_DONE;
	hdr->nlmsg_flags = 0;
	hdr->nlmsg_seq = 0;
	hdr->nlmsg_pid = getpid();

	msg = (struct cn_msg *)NLMSG_DATA(hdr);
	msg->id.idx = CN_IDX_PROC;
	msg->id.val = CN_VAL_PROC;
	msg->seq = 0;
	msg->ack = 0;
	msg->flags = 0;

	msg->len = sizeof(struct proc_input);
	((struct proc_input *)msg->data)->mcast_op =
		PROC_CN_MCAST_NOTIFY;
	((struct proc_input *)msg->data)->uexit_code = exit_code;

	if (send(nl_sock, hdr, hdr->nlmsg_len, 0) == -1) {
		perror("send failed");
		return -errno;
	}
	return 0;
}

int notify_netlink_thread_exit(unsigned int exit_code)
{
	struct sockaddr_nl sa_nl;
	int err = 0;
	int nl_sock;

	nl_sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);

	if (nl_sock == -1) {
		perror("socket failed");
		return -errno;
	}

	bzero(&sa_nl, sizeof(sa_nl));
	sa_nl.nl_family = AF_NETLINK;
	sa_nl.nl_groups = CN_IDX_PROC;
	sa_nl.nl_pid    = gettid();

	if (bind(nl_sock, (struct sockaddr *)&sa_nl, sizeof(sa_nl)) == -1) {
		perror("bind failed");
		close(nl_sock);
		return -errno;
	}

	err = send_message(nl_sock, exit_code);

	close(nl_sock);

	if (err < 0)
		return err;

	return 0;
}
