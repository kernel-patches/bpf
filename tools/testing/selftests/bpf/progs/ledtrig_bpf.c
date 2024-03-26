// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


extern void bpf_ledtrig_blink(const char *led_name, unsigned long delay_on,
		unsigned long delay_off, int invert) __weak __ksym;


SEC("perf_event")
int perf_blink(void)
{
	const char *led = "test_led";

	bpf_ledtrig_blink(led, 30, 30, 0);
	return 0;
}


SEC("syscall")
int fork_blink(void)
{
	const char *led = "test_led";

	bpf_ledtrig_blink(led, 30, 30, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
