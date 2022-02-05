// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Facebook */

#include <test_progs.h>
#include "test_custom_sec_handlers.skel.h"

#define COOKIE_ABC1 1
#define COOKIE_ABC2 2
#define COOKIE_CUSTOM 3
#define COOKIE_FALLBACK 4

static int custom_init_prog(struct bpf_program *prog, long cookie)
{
	if (cookie == COOKIE_ABC1)
		bpf_program__set_autoload(prog, false);

	return 0;
}

static int custom_preload_prog(struct bpf_program *prog,
			       struct bpf_prog_load_opts *opts, long cookie)
{
	return 0;
}

static int custom_attach_prog(const struct bpf_program *prog, long cookie,
			      struct bpf_link **link)
{
	switch (cookie) {
	case COOKIE_ABC2:
		*link = bpf_program__attach_raw_tracepoint(prog, "sys_enter");
		return libbpf_get_error(*link);
	case COOKIE_CUSTOM:
		*link = bpf_program__attach_tracepoint(prog, "syscalls", "sys_enter_nanosleep");
		return libbpf_get_error(*link);
	case COOKIE_FALLBACK:
		/* no auto-attach for SEC("xyz") */
		*link = NULL;
		return 0;
	default:
		ASSERT_FALSE(true, "unexpected cookie");
		return -EINVAL;
	}
}

static int abc1_id;
static int abc2_id;
static int custom_id;
static int fallback_id;

__attribute__((constructor))
static void register_sec_handlers(void)
{
	abc1_id = libbpf_register_prog_handler("abc",
					       BPF_PROG_TYPE_RAW_TRACEPOINT, 0,
					       custom_init_prog, custom_preload_prog,
					       custom_attach_prog,
					       COOKIE_ABC1, NULL);
	abc2_id = libbpf_register_prog_handler("abc/",
					       BPF_PROG_TYPE_RAW_TRACEPOINT, 0,
					       custom_init_prog, custom_preload_prog,
					       custom_attach_prog,
					       COOKIE_ABC2, NULL);
	custom_id = libbpf_register_prog_handler("custom+",
						 BPF_PROG_TYPE_TRACEPOINT, 0,
						 custom_init_prog, custom_preload_prog,
						 custom_attach_prog,
						 COOKIE_CUSTOM, NULL);
}

__attribute__((destructor))
static void unregister_sec_handlers(void)
{
	libbpf_unregister_prog_handler(abc1_id);
	libbpf_unregister_prog_handler(abc2_id);
	libbpf_unregister_prog_handler(custom_id);
}

void test_custom_sec_handlers(void)
{
	struct test_custom_sec_handlers* skel;
	int err;

	ASSERT_GT(abc1_id, 0, "abc1_id");
	ASSERT_GT(abc2_id, 0, "abc2_id");
	ASSERT_GT(custom_id, 0, "custom_id");

	fallback_id = libbpf_register_prog_handler(NULL, /* fallback handler */
						   BPF_PROG_TYPE_KPROBE, 0,
						   custom_init_prog, custom_preload_prog,
						   custom_attach_prog,
						   COOKIE_FALLBACK, NULL);
	if (!ASSERT_GT(fallback_id, 0, "fallback_id"))
		return;

	/* open skeleton and validate assumptions */
	skel = test_custom_sec_handlers__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		goto cleanup;

	ASSERT_EQ(bpf_program__type(skel->progs.abc1), BPF_PROG_TYPE_RAW_TRACEPOINT, "abc1_type");
	ASSERT_FALSE(bpf_program__autoload(skel->progs.abc1), "abc1_autoload");

	ASSERT_EQ(bpf_program__type(skel->progs.abc2), BPF_PROG_TYPE_RAW_TRACEPOINT, "abc2_type");
	ASSERT_EQ(bpf_program__type(skel->progs.custom1), BPF_PROG_TYPE_TRACEPOINT, "custom1_type");
	ASSERT_EQ(bpf_program__type(skel->progs.custom2), BPF_PROG_TYPE_TRACEPOINT, "custom2_type");
	ASSERT_EQ(bpf_program__type(skel->progs.xyz), BPF_PROG_TYPE_KPROBE, "xyz_type");

	skel->rodata->my_pid = getpid();

	/* now attempt to load everything */
	err = test_custom_sec_handlers__load(skel);
	if (!ASSERT_OK(err, "skel_load"))
		goto cleanup;

	/* now try to auto-attach everything */
	err = test_custom_sec_handlers__attach(skel);
	if (!ASSERT_OK(err, "skel_attach"))
		goto cleanup;

	/* trigger programs */
	usleep(1);

	/* SEC("abc") is set to not auto-loaded */
	ASSERT_FALSE(skel->bss->abc1_called, "abc1_called");
	ASSERT_TRUE(skel->bss->abc2_called, "abc2_called");
	ASSERT_TRUE(skel->bss->custom1_called, "custom1_called");
	ASSERT_TRUE(skel->bss->custom2_called, "custom2_called");
	/* SEC("xyz") shouldn't be auto-attached */
	ASSERT_FALSE(skel->bss->xyz_called, "xyz_called");

cleanup:
	test_custom_sec_handlers__destroy(skel);

	ASSERT_OK(libbpf_unregister_prog_handler(fallback_id), "unregister_fallback");
}
