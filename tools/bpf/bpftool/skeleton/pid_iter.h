/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __PID_ITER_H
#define __PID_ITER_H

#include <linux/sched/task.h>

struct pid_iter_entry {
	__u32 id;
	int pid;
	char comm[TASK_COMM_LEN_16];
};

#endif
