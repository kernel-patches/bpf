/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021 Telegram FZ-LLC
 */

#ifndef NET_BPFILTER_CONTEXT_H
#define NET_BPFILTER_CONTEXT_H

#include <stdio.h>

struct context {
	FILE *log_file;
	int log_level;
};

#endif // NET_BPFILTER_CONTEXT_H
