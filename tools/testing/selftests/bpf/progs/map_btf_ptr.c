#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

#define xchg(dst, src) __sync_lock_test_and_set(&(dst), (src))

struct map_value {
	struct prog_test_ref_kfunc __kptr *unref_ptr;
	/* Workarounds for https://lore.kernel.org/bpf/20220220071333.sltv4jrwniool2qy@apollo.legion */
	struct prog_test_ref_kfunc __kptr __attribute__((btf_type_tag("kernel.bpf.ref"))) *ref_ptr;
	struct prog_test_ref_kfunc __kptr __attribute__((btf_type_tag("kernel.bpf.percpu"))) *percpu_ptr;
	struct prog_test_ref_kfunc __kptr __attribute__((btf_type_tag("kernel.bpf.user"))) *user_ptr;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct map_value);
	__uint(max_entries, 1);
} array_map SEC(".maps");

extern struct prog_test_ref_kfunc *bpf_kfunc_call_test_acquire(unsigned long *sp) __ksym;
extern void bpf_kfunc_call_test_release(struct prog_test_ref_kfunc *p) __ksym;

SEC("tc")
int map_btf_ptr(struct __sk_buff *ctx)
{
	struct prog_test_ref_kfunc *p;
	char buf[sizeof(*p)];
	struct map_value *v;

	v = bpf_map_lookup_elem(&array_map, &(int){0});
	if (!v)
		return 0;
	p = v->unref_ptr;
	/* store untrusted_ptr_or_null_ */
	v->unref_ptr = p;
	if (!p)
		return 0;
	if (p->a + p->b > 100)
		return 1;
	/* store untrusted_ptr_ */
	v->unref_ptr = p;
	/* store NULL */
	v->unref_ptr = NULL;

	p = v->ref_ptr;
	/* store ptr_or_null_ */
	v->unref_ptr = p;
	if (!p)
		return 0;
	if (p->a + p->b > 100)
		return 1;
	/* store NULL */
	p = xchg(v->ref_ptr, NULL);
	if (!p)
		return 0;
	if (p->a + p->b > 100) {
		bpf_kfunc_call_test_release(p);
		return 1;
	}
	/* store ptr_ */
	v->unref_ptr = p;
	bpf_kfunc_call_test_release(p);

	p = bpf_kfunc_call_test_acquire(&(unsigned long){0});
	if (!p)
		return 0;
	/* store ptr_ */
	p = xchg(v->ref_ptr, p);
	if (!p)
		return 0;
	if (p->a + p->b > 100) {
		bpf_kfunc_call_test_release(p);
		return 1;
	}
	bpf_kfunc_call_test_release(p);

	p = v->percpu_ptr;
	/* store percpu_ptr_or_null_ */
	v->percpu_ptr = p;
	if (!p)
		return 0;
	p = bpf_this_cpu_ptr(p);
	if (p->a + p->b > 100)
		return 1;
	/* store percpu_ptr_ */
	v->percpu_ptr = p;
	/* store NULL */
	v->percpu_ptr = NULL;

	p = v->user_ptr;
	/* store user_ptr_or_null_ */
	v->user_ptr = p;
	if (!p)
		return 0;
	bpf_probe_read_user(buf, sizeof(buf), p);
	/* store user_ptr_ */
	v->user_ptr = p;
	/* store NULL */
	v->user_ptr = NULL;
	return 0;
}

char _license[] SEC("license") = "GPL";
