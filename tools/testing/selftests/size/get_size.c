// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright 2014 Sony Mobile Communications Inc.
 *
 * Selftest for runtime system size
 *
 * Prints the amount of RAM that the currently running system is using.
 *
 * This program tries to be as small as possible itself, to
 * avoid perturbing the system memory utilization with its
 * own execution.  It also attempts to have as few dependencies
 * on kernel features as possible.
 *
 * It is statically linked with nolibc startup and syscall wrappers.
 * For output, it avoids printf by implementing its own print routines.
 */

#include <nolibc.h>
#include <linux/sysinfo.h>

static int print(const char *s)
{
	size_t len = 0;

	while (s[len] != '\0')
		len++;

	return write(STDOUT_FILENO, s, len);
}

static inline char *num_to_str(unsigned long num, char *buf, int len)
{
	unsigned int digit;

	/* put digits in buffer from back to front */
	buf += len - 1;
	*buf = 0;
	do {
		digit = num % 10;
		*(--buf) = digit + '0';
		num /= 10;
	} while (num > 0);

	return buf;
}

static int print_num(unsigned long num)
{
	char num_buf[30];

	return print(num_to_str(num, num_buf, sizeof(num_buf)));
}

static int print_k_value(const char *s, unsigned long num, unsigned long units)
{
	unsigned long long temp;
	int ccode;

	print(s);

	temp = num;
	temp = (temp * units)/1024;
	num = temp;
	ccode = print_num(num);
	print("\n");
	return ccode;
}

int main(void)
{
	int ccode;
	struct sysinfo info;
	unsigned long used;
	static const char *test_name = " get runtime memory use\n";

	print("TAP version 13\n");
	print("# Testing system size.\n");

	ccode = syscall(__NR_sysinfo, &info);
	if (ccode < 0) {
		print("not ok 1");
		print(test_name);
		print(" ---\n reason: \"could not get sysinfo\"\n ...\n");
		return 1;
	}
	print("ok 1");
	print(test_name);

	/* ignore cache complexities for now */
	used = info.totalram - info.freeram - info.bufferram;
	print("# System runtime memory report (units in Kilobytes):\n");
	print(" ---\n");
	print_k_value(" Total:  ", info.totalram, info.mem_unit);
	print_k_value(" Free:   ", info.freeram, info.mem_unit);
	print_k_value(" Buffer: ", info.bufferram, info.mem_unit);
	print_k_value(" In use: ", used, info.mem_unit);
	print(" ...\n");
	print("1..1\n");

	return 0;
}
