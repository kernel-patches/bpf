// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

extern void bpf_kfunc_kasan_poison(void *mem, __u32 mem__sz) __ksym;
extern void bpf_kfunc_kasan_unpoison(void *mem, __u32 mem__sz) __ksym;

int access_size;

struct kasan_write_val {
	__u8 data_1;
	__u16 data_2;
	__u32 data_4;
	__u64 data_8;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct kasan_write_val);
} test_map SEC(".maps");

SEC("tcx/ingress")
int st(struct __sk_buff *skb)
{
	struct kasan_write_val *val;
	__u32 key = 0;

	val = bpf_map_lookup_elem(&test_map, &key);
	if (!val)
		return 0;

	bpf_kfunc_kasan_poison(val, sizeof(struct kasan_write_val));
	switch (access_size) {
	case 1:
		*(volatile __u8 *)&val->data_1 = 0xAA;
		break;
	case 2:
		*(volatile __u16 *)&val->data_2 = 0xAA;
		break;
	case 4:
		*(volatile __u32 *)&val->data_4 = 0xAA;
		break;
	case 8:
		*(volatile __u64 *)&val->data_8 = 0xAA;
		break;
	}
	bpf_kfunc_kasan_unpoison(val, sizeof(struct kasan_write_val));
	return 0;
}

SEC("tcx/ingress")
int stx(struct __sk_buff *skb)
{
	struct kasan_write_val *val;
	__u32 key = 0;

	val = bpf_map_lookup_elem(&test_map, &key);
	if (!val)
		return 0;

	bpf_kfunc_kasan_poison(val, sizeof(struct kasan_write_val));
	switch (access_size) {
	case 1:
		val->data_1 = access_size;
		break;
	case 2:
		val->data_2 = access_size;
		break;
	case 4:
		val->data_4 = access_size;
		break;
	case 8:
		val->data_8 = access_size;
		break;
	}
	bpf_kfunc_kasan_poison(val, sizeof(struct kasan_write_val));
	return 0;
}

SEC("tcx/ingress")
int ldx(struct __sk_buff *skb)
{
	struct kasan_write_val *val;
	__u32 key = 0;
	__u8 tmp_1;
	__u16 tmp_2;
	__u32 tmp_4;
	__u64 tmp_8;

	val = bpf_map_lookup_elem(&test_map, &key);
	if (!val)
		return 0;

	bpf_kfunc_kasan_poison(val, sizeof(struct kasan_write_val));
	switch (access_size) {
	case 1:
		*(volatile __u8 *)&tmp_1 = val->data_1;
		break;
	case 2:
		*(volatile __u16 *)&tmp_2 = val->data_2;
		break;
	case 4:
		*(volatile __u32 *)&tmp_4 = val->data_4;
		break;
	case 8:
		*(volatile __u64 *)&tmp_8 = val->data_8;
		break;
	}
	bpf_kfunc_kasan_unpoison(val, sizeof(struct kasan_write_val));
	return 0;
}

SEC("tcx/ingress")
int simple_atomic(struct __sk_buff *skb)
{
	struct kasan_write_val *val;
	__u32 key = 0;

	val = bpf_map_lookup_elem(&test_map, &key);
	if (!val)
		return 0;

	bpf_kfunc_kasan_poison(val, sizeof(struct kasan_write_val));
	switch (access_size) {
	case 4:
		__sync_fetch_and_add(&val->data_4, 4);
		break;
	case 8:
		__sync_fetch_and_add(&val->data_8, 8);
		break;
	}
	bpf_kfunc_kasan_unpoison(val, sizeof(struct kasan_write_val));
	return 0;
}

#ifdef __BPF_FEATURE_LOAD_ACQ_STORE_REL
int skip_load_acq_store_rel_tests __attribute__((section(".data"))) = 0;

SEC("tcx/ingress")
int load_acquire(struct __sk_buff *skb)
{
	struct kasan_write_val *val;
	__u32 key = 0;

	val = bpf_map_lookup_elem(&test_map, &key);
	if (!val)
		return 0;

	bpf_kfunc_kasan_poison(val, sizeof(struct kasan_write_val));
	switch (access_size) {
	case 1:
		__atomic_load_n(&val->data_1, __ATOMIC_ACQUIRE);
		break;
	case 2:
		__atomic_load_n(&val->data_2, __ATOMIC_ACQUIRE);
		break;
	case 4:
		__atomic_load_n(&val->data_4, __ATOMIC_ACQUIRE);
		break;
	case 8:
		__atomic_load_n(&val->data_8, __ATOMIC_ACQUIRE);
		break;
	}
	bpf_kfunc_kasan_unpoison(val, sizeof(struct kasan_write_val));
	return 0;
}

SEC("tcx/ingress")
int store_release(struct __sk_buff *skb)
{
	struct kasan_write_val *val;
	__u32 key = 0;

	val = bpf_map_lookup_elem(&test_map, &key);
	if (!val)
		return 0;

	bpf_kfunc_kasan_poison(val, sizeof(struct kasan_write_val));
	switch (access_size) {
	case 1:
		__atomic_store_n(&val->data_1, 0xAA, __ATOMIC_RELEASE);
		break;
	case 2:
		__atomic_store_n(&val->data_2, 0xBBBB, __ATOMIC_RELEASE);
		break;
	case 4:
		__atomic_store_n(&val->data_4, 0xCCCCCCCC, __ATOMIC_RELEASE);
		break;
	case 8:
		__atomic_store_n(&val->data_8, 0xDDDDDDDDDDDDDDDD,
				 __ATOMIC_RELEASE);
		break;
	}
	bpf_kfunc_kasan_unpoison(val, sizeof(struct kasan_write_val));
	return 0;
}
#else
int skip_load_acq_store_rel_tests __attribute__((section(".data"))) = 1;
#endif

char LICENSE[] SEC("license") = "GPL";
