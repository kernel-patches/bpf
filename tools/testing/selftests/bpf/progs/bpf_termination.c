// SPDX-License-Identifier: GPL-2.0
#include <stddef.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

int pid;

#define LOOPS_CNT 1 << 10

static int callback_fn4(void *ctx) {
	return 0;
}

static int callback_fn3(void *ctx) {
	bpf_loop(LOOPS_CNT, callback_fn4, NULL, 0);
	return 0;
}


static int callback_fn2(void *ctx) {
	bpf_loop(LOOPS_CNT, callback_fn3, NULL, 0);
	return 0;
}

static int callback_fn(void *ctx) {
	bpf_loop(LOOPS_CNT, callback_fn2, NULL, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_socket")
int bpf_loop_lr(void *ctx) {
	if ((bpf_get_current_pid_tgid() >> 32) != pid)
		return 0;
	bpf_loop(LOOPS_CNT, callback_fn, NULL, 0);
	return 0;
}

char _license[] SEC("license") = "GPL";
