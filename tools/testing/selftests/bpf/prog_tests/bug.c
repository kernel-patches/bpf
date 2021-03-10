#include <test_progs.h>
#include "test_bug.skel.h"

static int duration;

void test_bug(void)
{
	struct test_bug *skel;
	struct bpf_link *link;
	char buf[64] = {};
	int iter_fd, len;

	skel = test_bug__open_and_load();
	if (CHECK(!skel, "test_bug__open_and_load",
		  "skeleton open_and_load failed\n"))
		goto destroy;

	link = bpf_program__attach_iter(skel->progs.bug, NULL);
	if (CHECK(IS_ERR(link), "attach_iter", "attach_iter failed\n"))
		goto destroy;

	iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (CHECK(iter_fd < 0, "create_iter", "create_iter failed\n"))
		goto free_link;

	len = read(iter_fd, buf, sizeof(buf));
	CHECK(len < 0, "read", "read failed: %s\n", strerror(errno));
	// BUG: We expect the strings to be printed in both cases but only the
	// second case works.
	// actual 'str1= str2= str1=STR1 str2=STR2 '
	// != expected 'str1=STR1 str2=STR2 str1=STR1 str2=STR2 '
	ASSERT_STREQ(buf, "str1=STR1 str2=STR2 str1=STR1 str2=STR2 ", "read");

	close(iter_fd);

free_link:
	bpf_link__destroy(link);
destroy:
	test_bug__destroy(skel);
}

