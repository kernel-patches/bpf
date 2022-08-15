// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

struct map_value {
	unsigned long data;
	unsigned long data2;
	struct prog_test_ref_kfunc __kptr_ref *ptr;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct map_value);
	__uint(max_entries, 16);
} array_map SEC(".maps");

extern struct prog_test_ref_kfunc *bpf_kfunc_call_test_acquire(unsigned long *sp) __ksym;
extern void bpf_kfunc_call_test_release(struct prog_test_ref_kfunc *p) __ksym;

static __always_inline int cb1(void *map, void *key, void *value, void *ctx)
{
	void *p = *(void **)ctx;
	bpf_kfunc_call_test_release(p);
	/* Without the fix this would cause underflow */
	return 0;
}

SEC("?tc")
int underflow_prog(void *ctx)
{
	struct prog_test_ref_kfunc *p;
	unsigned long sl = 0;

	p = bpf_kfunc_call_test_acquire(&sl);
	if (!p)
		return 0;
	bpf_for_each_map_elem(&array_map, cb1, &p, 0);
	return 0;
}

static __always_inline int cb2(void *map, void *key, void *value, void *ctx)
{
	unsigned long sl = 0;

	*(void **)ctx = bpf_kfunc_call_test_acquire(&sl);
	/* Without the fix this would leak memory */
	return 0;
}

SEC("?tc")
int leak_prog(void *ctx)
{
	struct prog_test_ref_kfunc *p;
	struct map_value *v;
	unsigned long sl;

	v = bpf_map_lookup_elem(&array_map, &(int){0});
	if (!v)
		return 0;

	p = NULL;
	bpf_for_each_map_elem(&array_map, cb2, &p, 0);
	p = bpf_kptr_xchg(&v->ptr, p);
	if (p)
		bpf_kfunc_call_test_release(p);
	return 0;
}

static __always_inline int cb(void *map, void *key, void *value, void *ctx)
{
	return 0;
}

static __always_inline int cb3(void *map, void *key, void *value, void *ctx)
{
	unsigned long sl = 0;
	void *p;

	bpf_kfunc_call_test_acquire(&sl);
	bpf_for_each_map_elem(&array_map, cb, &p, 0);
	/* It should only complain here, not in cb. This is why we need
	 * callback_ref to be set to frameno.
	 */
	return 0;
}

SEC("?tc")
int nested_cb(void *ctx)
{
	int p = 0;

	bpf_for_each_map_elem(&array_map, cb3, &p, 0);
	return 0;
}

static __always_inline int lcb(void *map, unsigned long *idx)
{
	unsigned long i = *idx;
	i++;
	*idx = i;
	return 0;
}

SEC("?tc")
int oob_access(void *ctx)
{
	unsigned long idx = 0;
	struct map_value *v;

	v = bpf_map_lookup_elem(&array_map, &(int){0});
	if (!v)
		return 0;
	bpf_loop(100, lcb, &idx, 0);
	/* Verifier would think we are accessing using idx=1 without the fix */
	return ((unsigned long *)&v->data)[idx];
}

static __always_inline int lcb1(void *map, int *idx)
{
	int i = *idx;
	i--;
	*idx = i;
	return 0;
}

static __always_inline int lcb2(void *map, void **pp)
{
	int i = *(int *)(pp + 1);
	pp[i + 2] = (void *)0xeB9F15D34D;
	return 0;
}

SEC("?tc")
int write(void *ctx)
{
	struct {
		struct map_value *v;
		int idx;
	} x = {};
	x.v = bpf_map_lookup_elem(&array_map, &(int){0});
	if (!x.v)
		return 0;
	bpf_loop(2, &lcb1, &x.idx, 0);
	/* idx is -2, verifier thinks it is -1 */
	bpf_loop(1, &lcb2, &x, 0);
	/* x.v is no longer map value, but verifier thinks so */
	return x.v->data;
}

char _license[] SEC("license") = "GPL";
