// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <errno.h>

/* TODO - can we plumb better constants through here?
 * 40: sizeof(struct xdp_frame)
 * 16: sizeof(struct __trait_hdr)
 */
#define MAX_SPACE (XDP_PACKET_HEADROOM - 40 - 16)

/* For xdp_adjust_meta() */
#ifndef ENOTSUPP
#define ENOTSUPP 524
#endif

extern int bpf_xdp_trait_set(const struct xdp_md *xdp, __u64 key,
			     const void *val, __u64 val__sz,
			     __u64 flags) __ksym;
extern int bpf_xdp_trait_get(const struct xdp_md *xdp, __u64 key, void *val,
			     __u64 val__sz) __ksym;
extern int bpf_xdp_trait_del(const struct xdp_md *xdp, __u64 key) __ksym;
extern int bpf_xdp_trait_is_set(const struct xdp_md *xdp, __u64 key) __ksym;

#define ASSERT_CALL(WANT, CALL) do {							\
	int _ret = CALL;								\
	if (_ret != WANT) {								\
		bpf_printk("%d: %s ret %d want %d", __LINE__, #CALL, _ret, WANT);	\
		return XDP_DROP;							\
	}										\
} while (0)

#define ASSERT_VAL(WANT, GOT, PTRSIZE) do {								\
	if (__builtin_memcmp(WANT, GOT, PTRSIZE)) {							\
		switch (PTRSIZE) {									\
		case 0:											\
			return XDP_DROP;								\
		case 4:											\
			bpf_printk("%d: got %d want %d", __LINE__, *(__u32 *)GOT, *(__u32 *)WANT);	\
			return XDP_DROP;								\
		case 8:											\
			bpf_printk("%d: got %d want %d", __LINE__, *(__u64 *)GOT, *(__u64 *)WANT);	\
			return XDP_DROP;								\
		}											\
	}												\
} while (0)

#define FILL(PTR, PTRSIZE, VAL) do {			\
	int _i;						\
	for (_i = 0; _i < PTRSIZE; _i++)		\
		*(((__u8 *)(PTR))+_i) = (__u8)VAL;	\
} while (0)

static __always_inline int test(struct xdp_md *xdp, void *val, void *got, int valsize)
{
	int i, numkeys;

	numkeys = 64;
	if (valsize * numkeys > MAX_SPACE)
		numkeys = MAX_SPACE / valsize;

	/* No keys to start */
	for (i = 0; i < numkeys; i++) {
		ASSERT_CALL(-ENOENT, bpf_xdp_trait_get(xdp, i, val, valsize));
		ASSERT_CALL(-ENOENT, bpf_xdp_trait_del(xdp, i));
		ASSERT_CALL(0, bpf_xdp_trait_is_set(xdp, i));
	}

	/* Set all keys */
	for (i = 0; i < numkeys; i++) {
		FILL(val, valsize, i);
		ASSERT_CALL(0, bpf_xdp_trait_set(xdp, i, val, valsize, 0));

		ASSERT_CALL(valsize, bpf_xdp_trait_get(xdp, i, got, valsize));
		ASSERT_VAL(val, got, valsize);
		ASSERT_CALL(1, bpf_xdp_trait_is_set(xdp, i));
	}

	/* Get all keys back out */
	for (i = 0; i < numkeys; i++) {
		FILL(val, valsize, i);

		ASSERT_CALL(valsize, bpf_xdp_trait_get(xdp, i, got, valsize));
		ASSERT_VAL(val, got, valsize);
		ASSERT_CALL(1, bpf_xdp_trait_is_set(xdp, i));
	}

	/* Overwrite all keys */
	for (i = 0; i < numkeys; i++) {
		FILL(val, valsize, i+128);
		ASSERT_CALL(0, bpf_xdp_trait_set(xdp, i, val, valsize, 0));
	}

	/* Delete all even keys */
	for (i = 0; i < numkeys; i++) {
		if (!(i & 1))
			ASSERT_CALL(0, bpf_xdp_trait_del(xdp, i));
	}

	/* Check remaining keys */
	for (i = 0; i < numkeys; i++) {
		if (!(i & 1)) {
			ASSERT_CALL(-ENOENT, bpf_xdp_trait_get(xdp, i, val, valsize));
			ASSERT_CALL(0, bpf_xdp_trait_is_set(xdp, i));
		} else {
			FILL(val, valsize, i+128);

			ASSERT_CALL(valsize, bpf_xdp_trait_get(xdp, i, got, valsize));
			ASSERT_VAL(val, got, valsize);
		}
	}

	return XDP_PASS;
}

SEC("xdp")
int xdp_traits_0(struct xdp_md *xdp)
{
	return test(xdp, NULL, NULL, 0);
}

SEC("xdp")
int xdp_traits_4(struct xdp_md *xdp)
{
	__u32 a, b;

	return test(xdp, &a, &b, sizeof(a));
}

SEC("xdp")
int xdp_traits_8(struct xdp_md *xdp)
{
	__u64 a, b;

	return test(xdp, &a, &b, sizeof(a));
}

SEC("xdp")
int xdp_traits_invalid_key(struct xdp_md *xdp)
{
	ASSERT_CALL(-EINVAL, bpf_xdp_trait_get(xdp, 65, NULL, 0));
	ASSERT_CALL(-EINVAL, bpf_xdp_trait_set(xdp, 65, NULL, 0, 0));
	ASSERT_CALL(-EINVAL, bpf_xdp_trait_del(xdp, 65));
	ASSERT_CALL(-EINVAL, bpf_xdp_trait_is_set(xdp, 65));
	return XDP_PASS;
}

SEC("xdp")
int xdp_traits_invalid_len(struct xdp_md *xdp)
{
	__u8 v;

	ASSERT_CALL(-EINVAL, bpf_xdp_trait_set(xdp, 0, &v, sizeof(v), 0));
	return XDP_PASS;
}

SEC("xdp")
int xdp_traits_len_too_small(struct xdp_md *xdp)
{
	__u8 v1;
	__u32 v4;

	ASSERT_CALL(0, bpf_xdp_trait_set(xdp, 0, &v4, sizeof(v4), 0));
	ASSERT_CALL(-ENOSPC, bpf_xdp_trait_get(xdp, 0, &v1, sizeof(v1)));
	return XDP_PASS;
}

SEC("xdp")
int xdp_traits_different_len(struct xdp_md *xdp)
{
	__u32 v;

	ASSERT_CALL(0, bpf_xdp_trait_set(xdp, 0, &v, sizeof(v), 0));
	ASSERT_CALL(-EBUSY, bpf_xdp_trait_set(xdp, 0, NULL, 0, 0));
	return XDP_PASS;
}

SEC("xdp")
int xdp_traits_no_space(struct xdp_md *xdp)
{
	int i;
	__u64 v;

	for (i = 0; i < MAX_SPACE / 8; i++)
		ASSERT_CALL(0, bpf_xdp_trait_set(xdp, i, &v, sizeof(v), 0));
	ASSERT_CALL(-ENOSPC, bpf_xdp_trait_set(xdp, i+1, &v, sizeof(v), 0));
	return XDP_PASS;
}

SEC("xdp")
int xdp_meta_then_traits(struct xdp_md *xdp)
{
	ASSERT_CALL(0, bpf_xdp_adjust_meta(xdp, -8));
	ASSERT_CALL(-EOPNOTSUPP, bpf_xdp_trait_set(xdp, 0, NULL, 0, 0));
	return XDP_PASS;
}

SEC("xdp")
int xdp_traits_then_meta(struct xdp_md *xdp)
{
	ASSERT_CALL(0, bpf_xdp_trait_set(xdp, 0, NULL, 0, 0));
	ASSERT_CALL(-ENOTSUPP, bpf_xdp_adjust_meta(xdp, -8));
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
