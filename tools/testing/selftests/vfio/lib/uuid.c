// SPDX-License-Identifier: GPL-2.0-only
#include <string.h>

#include <libvfio.h>

#define UUID_STRING_LEN	36

static int hexval(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

int uuid_parse(const char *in, uuid_t uu)
{
	const char *p = in;
	int i, hi, lo;

	if (strlen(in) != UUID_STRING_LEN)
		return -1;

	for (i = 0; i < UUID_SIZE; i++) {
		if (i == 4 || i == 6 || i == 8 || i == 10) {
			if (*p++ != '-')
				return -1;
		}

		hi = hexval(*p++);
		lo = hexval(*p++);
		if (hi < 0 || lo < 0)
			return -1;

		uu[i] = (hi << 4) | lo;
	}

	return 0;
}
