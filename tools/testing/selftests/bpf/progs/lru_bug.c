// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

struct map_value {
	struct prog_test_ref_kfunc __kptr_ref *ptr;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct map_value);
} lru_map SEC(".maps");

extern struct prog_test_ref_kfunc *bpf_kfunc_call_test_acquire(unsigned long *sp) __ksym;
extern void bpf_kfunc_call_test_release(struct prog_test_ref_kfunc *s) __ksym;

int pid = 0;
const volatile int debug = 0;
int result = 1;

SEC("fentry/bpf_ktime_get_ns")
int printk(void *ctx)
{
	struct map_value v = {};

	if (pid == bpf_get_current_task_btf()->pid)
		bpf_map_update_elem(&lru_map, &(int){0}, &v, 0);
	return 0;
}

SEC("fentry/do_nanosleep")
int nanosleep(void *ctx)
{
	struct map_value val = {}, *v;
	struct prog_test_ref_kfunc *s;
	unsigned long l = 0;

	bpf_map_update_elem(&lru_map, &(int){0}, &val, 0);
	v = bpf_map_lookup_elem(&lru_map, &(int){0});
	if (!v)
		return 0;
	bpf_map_delete_elem(&lru_map, &(int){0});
	s = bpf_kfunc_call_test_acquire(&l);
	if (!s)
		return 0;
	if (debug)
		bpf_printk("ref: %d\n", s->cnt.refs.counter);
	s = bpf_kptr_xchg(&v->ptr, s);
	if (s)
		bpf_kfunc_call_test_release(s);
	pid = bpf_get_current_task_btf()->pid;
	bpf_ktime_get_ns();
	if (debug) {
		s = bpf_kfunc_call_test_acquire(&l);
		if (!s)
			return 0;
		bpf_printk("ref: %d\n", s->cnt.refs.counter);
		bpf_kfunc_call_test_release(s);
	}
	result = !v->ptr;
	return 0;
}

char _license[] SEC("license") = "GPL";
