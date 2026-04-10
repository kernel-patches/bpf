// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define KASAN_SLAB_FREE 0xFB
#define KASAN_GLOBAL_REDZONE 0xF9

extern __u8 *bpf_kfunc_kasan_uaf_1(void) __ksym;
extern __u16 *bpf_kfunc_kasan_uaf_2(void) __ksym;
extern __u32 *bpf_kfunc_kasan_uaf_4(void) __ksym;
extern __u64 *bpf_kfunc_kasan_uaf_8(void) __ksym;
extern __u8 *bpf_kfunc_kasan_oob_1(void) __ksym;
extern __u16 *bpf_kfunc_kasan_oob_2(void) __ksym;
extern __u32 *bpf_kfunc_kasan_oob_4(void) __ksym;
extern __u64 *bpf_kfunc_kasan_oob_8(void) __ksym;
extern void bpf_kfunc_kasan_poison(void *mem, __u32 mem__sz, __u8 byte) __ksym;

int access_size;
int is_write;

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

static void bpf_kasan_faulty_write(int size, __u8 poison_byte)
{
	struct kasan_write_val *val;
	__u32 key = 0;

	val = bpf_map_lookup_elem(&test_map, &key);
	if (!val)
		return;

	bpf_kfunc_kasan_poison(val, sizeof(struct kasan_write_val),
			       poison_byte);
	switch (size) {
	case 1:
		val->data_1 = 0xAA;
		break;
	case 2:
		val->data_2 = 0xAA;
		break;
	case 4:
		val->data_4 = 0xAA;
		break;
	case 8:
		val->data_8 = 0xAA;
		break;
	}
	bpf_kfunc_kasan_poison(val, sizeof(struct kasan_write_val), 0x00);
}


static int bpf_kasan_uaf_read(int size)
{
	__u8 *result_1;
	__u16 *result_2;
	__u32 *result_4;
	__u64 *result_8;
	int ret = 0;

	switch (size) {
	case 1:
		result_1 = bpf_kfunc_kasan_uaf_1();
		ret = result_1[0] ? 1 : 0;
		break;
	case 2:
		result_2 = bpf_kfunc_kasan_uaf_2();
		ret = result_2[0] ? 1 : 0;
		break;
	case 4:
		result_4 = bpf_kfunc_kasan_uaf_4();
		ret = result_4[0] ? 1 : 0;
		break;
	case 8:
		result_8 = bpf_kfunc_kasan_uaf_8();
		ret = result_8[0] ? 1 : 0;
		break;
	}
	return ret;
}

SEC("tcx/ingress")
int bpf_kasan_uaf(struct __sk_buff *skb)
{
	if (is_write) {
		bpf_kasan_faulty_write(access_size, KASAN_SLAB_FREE);
		return 0;
	}

	return bpf_kasan_uaf_read(access_size);
}

static int bpf_kasan_oob_read(int size)
{
	__u8 *result_1;
	__u16 *result_2;
	__u32 *result_4;
	__u64 *result_8;
	int ret = 0;

	switch (size) {
	case 1:
		result_1 = bpf_kfunc_kasan_oob_1();
		ret = result_1[0] ? 1 : 0;
		break;
	case 2:
		result_2 = bpf_kfunc_kasan_oob_2();
		ret = result_2[0] ? 1 : 0;
		break;
	case 4:
		result_4 = bpf_kfunc_kasan_oob_4();
		ret = result_4[0] ? 1 : 0;
		break;
	case 8:
		result_8 = bpf_kfunc_kasan_oob_8();
		ret = result_8[0] ? 1 : 0;
		break;
	}
	return ret;
}

SEC("tcx/ingress")
int bpf_kasan_oob(struct __sk_buff *skb)
{
	if (is_write) {
		bpf_kasan_faulty_write(access_size, KASAN_GLOBAL_REDZONE);
		return 0;
	}

	return bpf_kasan_oob_read(access_size);
}

char LICENSE[] SEC("license") = "GPL";
