/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PRIVATE_STACK_RUNTIME_H
#define __PRIVATE_STACK_RUNTIME_H

struct private_stack_result {
	long value;
	long first;
	long last;
	__u32 cpu;
};

#endif
