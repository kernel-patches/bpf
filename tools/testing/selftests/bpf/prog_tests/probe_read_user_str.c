// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "test_probe_read_user_str.skel.h"

static const char str[] = "mestring";

void test_probe_read_user_str(void)
{
	struct test_probe_read_user_str *skel;
	int fd, err, duration = 0;
	char buf[256];
	ssize_t n;

	skel = test_probe_read_user_str__open_and_load();
	if (CHECK(!skel, "test_probe_read_user_str__open_and_load",
		  "skeleton open and load failed\n"))
		return;

	/* Give pid to bpf prog so it doesn't read from anyone else */
	skel->bss->pid = getpid();

	err = test_probe_read_user_str__attach(skel);
	if (CHECK(err, "test_probe_read_user_str__attach",
		  "skeleton attach failed: %d\n", err))
		goto out;

	fd = open("/dev/null", O_WRONLY);
	if (CHECK(fd < 0, "open", "open /dev/null failed: %d\n", fd))
		goto out;

	/* Ensure bytes after string are ones */
	memset(buf, 1, sizeof(buf));
	memcpy(buf, str, sizeof(str));

	/* Trigger tracepoint */
	n = write(fd, buf, sizeof(buf));
	if (CHECK(n != sizeof(buf), "write", "write failed: %ld\n", n))
		goto fd_out;

	/* Did helper fail? */
	if (CHECK(skel->bss->ret < 0, "prog_ret", "prog returned: %ld\n",
		  skel->bss->ret))
		goto fd_out;

	/* Check that string was copied correctly */
	err = memcmp(skel->bss->buf, str, sizeof(str));
	if (CHECK(err, "memcmp", "prog copied wrong string"))
		goto fd_out;

	/* Now check that no extra trailing bytes were copied */
	memset(buf, 0, sizeof(buf));
	err = memcmp(skel->bss->buf + sizeof(str), buf, sizeof(buf) - sizeof(str));
	if (CHECK(err, "memcmp", "trailing bytes were not stripped"))
		goto fd_out;

fd_out:
	close(fd);
out:
	test_probe_read_user_str__destroy(skel);
}
