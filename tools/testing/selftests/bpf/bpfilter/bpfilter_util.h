/* SPDX-License-Identifier: GPL-2.0 */

#ifndef BPFILTER_UTIL_H
#define BPFILTER_UTIL_H

#include <linux/bpf.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static inline int sys_bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
	return syscall(SYS_bpf, cmd, attr, size);
}

static inline int bpf_prog_test_run(int fd, const void *data,
				    unsigned int data_size, uint32_t *retval)
{
	union bpf_attr attr = {};
	int r;

	attr.test.prog_fd = fd;
	attr.test.data_in = (uintptr_t)data;
	attr.test.data_size_in = data_size;
	attr.test.repeat = 1000000;

	r = sys_bpf(BPF_PROG_TEST_RUN, &attr, sizeof(attr));

	if (retval)
		*retval = attr.test.retval;

	return r;
}

static inline void init_entry_match(struct xt_entry_match *match,
				    uint16_t size, uint8_t revision,
				    const char *name)
{
	memset(match, 0, sizeof(*match));
	sprintf(match->u.user.name, "%s", name);
	match->u.user.match_size = size;
	match->u.user.revision = revision;
}

static inline void init_standard_target(struct xt_standard_target *ipt_target,
					int revision, int verdict)
{
	snprintf(ipt_target->target.u.user.name,
		 sizeof(ipt_target->target.u.user.name), "%s",
		 BPFILTER_STANDARD_TARGET);
	ipt_target->target.u.user.revision = revision;
	ipt_target->target.u.user.target_size = sizeof(*ipt_target);
	ipt_target->verdict = verdict;
}

static inline void init_error_target(struct xt_error_target *ipt_target,
				     int revision, const char *error_name)
{
	snprintf(ipt_target->target.u.user.name,
		 sizeof(ipt_target->target.u.user.name), "%s",
		 BPFILTER_ERROR_TARGET);
	ipt_target->target.u.user.revision = revision;
	ipt_target->target.u.user.target_size = sizeof(*ipt_target);
	snprintf(ipt_target->errorname, sizeof(ipt_target->errorname), "%s",
		 error_name);
}

static inline void init_standard_entry(struct ipt_entry *entry, __u16 matches_size)
{
	memset(entry, 0, sizeof(*entry));
	entry->target_offset = sizeof(*entry) + matches_size;
	entry->next_offset = sizeof(*entry) + matches_size + sizeof(struct xt_standard_target);
}

#endif // BPFILTER_UTIL_H
