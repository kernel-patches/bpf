// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE
#include <test_progs.h>
#include <network_helpers.h>
#include <sys/stat.h>
#include <linux/sched.h>
#include <sys/syscall.h>

#include "test_trace_ext.skel.h"
#include "test_trace_ext_tracing.skel.h"

static __u32 duration;

void test_trace_ext(void)
{
	struct test_trace_ext_tracing *skel_trace = NULL;
	struct test_trace_ext_tracing__bss *bss_trace;
	const char *file = "./test_pkt_md_access.o";
	struct test_trace_ext *skel_ext = NULL;
	struct test_trace_ext__bss *bss_ext;
	int err, prog_fd, ext_fd;
	struct bpf_object *obj;
	char buf[100];
	__u32 retval;
	__u64 len;

	err = bpf_prog_load(file, BPF_PROG_TYPE_SCHED_CLS, &obj, &prog_fd);
	if (CHECK_FAIL(err))
		return;

	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts,
			    .attach_prog_fd = prog_fd,
	);

	skel_ext = test_trace_ext__open_opts(&opts);
	if (CHECK(!skel_ext, "setup", "freplace/test_pkt_md_access open failed\n"))
		goto cleanup;

	err = test_trace_ext__load(skel_ext);
	if (CHECK(err, "setup", "freplace/test_pkt_md_access load failed\n")) {
		libbpf_strerror(err, buf, sizeof(buf));
		fprintf(stderr, "%s\n", buf);
		goto cleanup;
	}

	err = test_trace_ext__attach(skel_ext);
	if (CHECK(err, "setup", "freplace/test_pkt_md_access attach failed: %d\n", err))
		goto cleanup;

	ext_fd = bpf_program__fd(skel_ext->progs.test_pkt_md_access_new);

	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts_trace,
			    .attach_prog_fd = ext_fd,
	);

	skel_trace = test_trace_ext_tracing__open_opts(&opts_trace);
	if (CHECK(!skel_trace, "setup", "tracing/test_pkt_md_access_new open failed\n"))
		goto cleanup;

	err = test_trace_ext_tracing__load(skel_trace);
	if (CHECK(err, "setup", "tracing/test_pkt_md_access_new load failed\n")) {
		libbpf_strerror(err, buf, sizeof(buf));
		fprintf(stderr, "%s\n", buf);
		goto cleanup;
	}

	err = test_trace_ext_tracing__attach(skel_trace);
	if (CHECK(err, "setup", "tracing/test_pkt_md_access_new attach failed: %d\n", err))
		goto cleanup;

	err = bpf_prog_test_run(prog_fd, 1, &pkt_v4, sizeof(pkt_v4),
				NULL, NULL, &retval, &duration);
	CHECK(err || retval, "",
	      "err %d errno %d retval %d duration %d\n",
	      err, errno, retval, duration);

	bss_ext = skel_ext->bss;
	bss_trace = skel_trace->bss;

	len = bss_ext->ext_called;

	CHECK(bss_ext->ext_called == 0,
		"check", "failed to trigger freplace/test_pkt_md_access\n");
	CHECK(bss_trace->fentry_called != len,
		"check", "failed to trigger fentry/test_pkt_md_access_new\n");
	CHECK(bss_trace->fexit_called != len,
		"check", "failed to trigger fexit/test_pkt_md_access_new\n");

cleanup:
	test_trace_ext__destroy(skel_ext);
	bpf_object__close(obj);
}
