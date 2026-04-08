// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <test_progs.h>
#include "testing_helpers.h"
#include "test_klp_bpf.skel.h"

#define KLP_MODULE_NAME "test_klp_bpf"
#define KLP_ENABLED_PATH "/sys/kernel/livepatch/" KLP_MODULE_NAME "/enabled"

static int load_klp_module(void)
{
	return load_module("test_klp_bpf.ko", env_verbosity > VERBOSE_NONE);
}

static void unload_klp_module(void)
{
	/* Disable the livepatch before unloading */
	if (!access(KLP_ENABLED_PATH, F_OK))
		system("echo 0 > " KLP_ENABLED_PATH);

	unload_module(KLP_MODULE_NAME, env_verbosity > VERBOSE_NONE);
}

static int read_proc_cmdline(char *buf, size_t buf_sz)
{
	int fd, ret;

	fd = open("/proc/cmdline", O_RDONLY);
	if (fd < 0)
		return -errno;

	ret = read(fd, buf, buf_sz - 1);
	close(fd);
	if (ret < 0)
		return -errno;

	buf[ret] = '\0';
	return 0;
}

void test_klp_bpf(void)
{
	struct test_klp_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	char buf[4096] = {};
	int err;

	/* Skip if kernel was built without CONFIG_LIVEPATCH */
	if (access("/sys/kernel/livepatch", F_OK)) {
		test__skip();
		return;
	}

	err = load_klp_module();
	if (err) {
		if (err == -ENOENT) {
			test__skip();
			return;
		}
		/* Module may already be loaded; unload and retry */
		unload_klp_module();
		err = load_klp_module();
		if (!ASSERT_OK(err, "load_klp_module"))
			return;
	}

	/* Verify livepatch is active with fallback message */
	err = read_proc_cmdline(buf, sizeof(buf));
	if (!ASSERT_OK(err, "read_cmdline_fallback"))
		goto out;
	if (!ASSERT_OK(strncmp(buf, "test_klp_bpf: no struct_ops attached",
			       strlen("test_klp_bpf: no struct_ops attached")),
		       "fallback_msg"))
		goto out;

	/* Load and attach BPF struct_ops */
	skel = test_klp_bpf__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		goto out;

	link = bpf_map__attach_struct_ops(skel->maps.cmdline_ops);
	if (!ASSERT_OK_PTR(link, "attach_struct_ops"))
		goto out;

	/* Verify BPF-controlled cmdline */
	memset(buf, 0, sizeof(buf));
	err = read_proc_cmdline(buf, sizeof(buf));
	if (!ASSERT_OK(err, "read_cmdline_bpf"))
		goto out;
	ASSERT_STREQ(buf, "klp_bpf: custom cmdline\n", "bpf_cmdline");

	/* Detach and verify fallback resumes */
	bpf_link__destroy(link);
	link = NULL;

	memset(buf, 0, sizeof(buf));
	err = read_proc_cmdline(buf, sizeof(buf));
	if (!ASSERT_OK(err, "read_cmdline_detached"))
		goto out;
	ASSERT_OK(strncmp(buf, "test_klp_bpf: no struct_ops attached",
			  strlen("test_klp_bpf: no struct_ops attached")),
		  "detached_fallback_msg");

out:
	bpf_link__destroy(link);
	test_klp_bpf__destroy(skel);
	unload_klp_module();
}
