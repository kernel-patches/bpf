// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Implement the UMD Handler.
 */
#include <unistd.h>
#include <malloc.h>
#include <stdint.h>

#include "msgfmt.h"

FILE *debug_f;

static void loop(void)
{
	struct sample_request *req = NULL;
	struct sample_reply *reply = NULL;

	req = calloc(1, sizeof(*req));
	if (!req)
		return;

	reply = calloc(1, sizeof(*reply));
	if (!reply)
		goto out;

	while (1) {
		int n, len, offset;

		offset = 0;
		len = sizeof(*req);

		while (len) {
			n = read(0, ((void *)req) + offset, len);
			if (n <= 0) {
				fprintf(debug_f, "invalid request %d\n", n);
				goto out;
			}

			len -= n;
			offset += n;
		}

		if (req->offset < sizeof(reply->data))
			reply->data[req->offset] = 1;

		offset = 0;
		len = sizeof(*reply);

		while (len) {
			n = write(1, ((void *)reply) + offset, len);
			if (n <= 0) {
				fprintf(debug_f, "reply failed %d\n", n);
				goto out;
			}

			len -= n;
			offset += n;
		}

		if (req->offset < sizeof(reply->data))
			reply->data[req->offset] = 0;
	}
out:
	free(req);
	free(reply);
}

int main(void)
{
	debug_f = fopen("/dev/kmsg", "w");
	setvbuf(debug_f, 0, _IOLBF, 0);
	fprintf(debug_f, "<5>Started sample_umh\n");
	loop();
	fclose(debug_f);

	return 0;
}
