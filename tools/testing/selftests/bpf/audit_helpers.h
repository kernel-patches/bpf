/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2026 Cloudflare */
#pragma once

#include <linux/audit.h>
#include <linux/netlink.h>
#include <stdio.h>

#define MAX_AUDIT_MESSAGE_LENGTH 8970

struct audit_message {
	struct nlmsghdr nlh;
	union {
		struct audit_status status;
		struct nlmsgerr err;
		char data[MAX_AUDIT_MESSAGE_LENGTH];
	};
};

/*
 * Observer-based audit message matching.
 * Tests register expected patterns before triggering events, then
 * wait for matches. Messages that don't match any pattern are skipped.
 */
#define AUDIT_EXPECT_MAX 32

struct audit_expectation {
	__u16 type;
	const char *pattern;
	int expected_count;
	int matched_count;
};

struct audit_observer {
	struct audit_expectation expects[AUDIT_EXPECT_MAX];
	int num_expects;
	FILE *log;
	int wait_timeout;
	int audit_fd;
};

int audit_init(void);
void audit_cleanup(int fd);
int audit_wait_ack(int fd);
int audit_send(int fd, __u16 type, __u32 key, __u32 val);
int audit_recv(int fd, struct audit_message *msg, int flags);
int audit_wait_ack(int fd);

void audit_observer_init(struct audit_observer *obs, int audit_fd, FILE *log,
			 int wait_timeout);
void audit_observer_reset(struct audit_observer *obs);
int audit_observer_expect(struct audit_observer *obs, int audit_type,
			  const char *pattern, int count);
int audit_observer_wait(struct audit_observer *obs);
int audit_observer_check_satisfied(struct audit_observer *obs);
