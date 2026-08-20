/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */
#ifndef __CGROUP_ITER_IO_H
#define __CGROUP_ITER_IO_H

struct io_query {
	/* one device's io.stat counters */
	__u64 rbytes;
	__u64 wbytes;
	__u64 rios;
	__u64 wios;
	__u64 dbytes;
	__u64 dios;
	__u64 dev;	/* dev_t of the device the counters belong to */
};

#endif /* __CGROUP_ITER_IO_H */
