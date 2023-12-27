// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

extern int bpf_relay_output(struct bpf_map *map, void *data,
				      __u64 data__sz, __u32 flags) __ksym;

struct relay_sample {
	int pid;
	int seq;
	long value;
	char comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_RELAY);
	__uint(max_entries, 1024);
} relay_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RELAY);
	__uint(map_flags, BPF_F_OVERWRITE);
	__uint(max_entries, 1024);
	__uint(map_extra, 1);
} relay_map_ow SEC(".maps");

/* inputs */
int pid = 0;
long value = 0;
int overwrite_enable = 0;

/* outputs */
long total = 0;
long dropped = 0;

/* inner state */
long seq = 0;

SEC("fentry/" SYS_PREFIX "sys_getpgid")
int test_bpf_relaymap(void *ctx)
{
	int cur_pid = bpf_get_current_pid_tgid() >> 32;
	struct relay_sample sample;
	int ret = 0;

	if (cur_pid != pid)
		return 0;

	sample.pid = pid;
	bpf_get_current_comm(sample.comm, sizeof(sample.comm));
	sample.value = value;
	sample.seq = seq++;
	__sync_fetch_and_add(&total, 1);

	if (overwrite_enable)
		ret = bpf_relay_output((struct bpf_map *)&relay_map_ow,
				      &sample, sizeof(sample), 0);
	else
		ret = bpf_relay_output((struct bpf_map *)&relay_map,
				      &sample, sizeof(sample), 0);

	if (ret)
		__sync_fetch_and_add(&dropped, 1);

	return 0;
}
