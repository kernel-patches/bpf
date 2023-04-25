// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Implement the UMD handler.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

#include "umd_key_sig_umh.h"

FILE *debug_f;

int main(int argc, char *argv[])
{
	struct msg_in *in = NULL;
	struct msg_out *out = NULL;
	size_t in_len, out_len;
	loff_t pos;
	int ret = 0;

#ifdef debug
	debug_f = fopen("/dev/kmsg", "a");
	fprintf(debug_f, "<5>Started %s\n", argv[0]);
	fflush(debug_f);
#endif
	in = malloc(sizeof(*in));
	if (!in)
		goto out;

	out = malloc(sizeof(*out));
	if (!out)
		goto out;

	while (1) {
		int n;

		in_len = sizeof(*in);
		out_len = sizeof(*out);

		memset(in, 0, in_len);
		memset(out, 0, out_len);

		pos = 0;
		while (in_len) {
			n = read(0, (void *)in + pos, in_len);
			if (n <= 0) {
				ret = -EIO;
				goto out;
			}
			in_len -= n;
			pos += n;
		}

		switch (in->cmd) {
		default:
			out->ret = -EOPNOTSUPP;
			break;
		}

		pos = 0;
		while (out_len) {
			n = write(1, (void *)out + pos, out_len);
			if (n <= 0) {
				ret = -EIO;
				goto out;
			}
			out_len -= n;
			pos += n;
		}
	}
out:
	free(in);
	free(out);
#ifdef debug
	fclose(debug_f);
#endif
	return ret;
}
