// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <errno.h>

extern int bpf_xdp_trait_set(const struct xdp_md *xdp, __u64 key,
			     const void *val, __u64 val__sz,
			     __u64 flags) __ksym;
extern int bpf_xdp_trait_get(const struct xdp_md *xdp, __u64 key, void *val,
			     __u64 val__sz) __ksym;
extern int bpf_xdp_trait_del(const struct xdp_md *xdp, __u64 key) __ksym;

__u32 trait_len;
long hits = 0;

#define ITERATIONS (10000)

SEC("xdp")
int trait_get(struct xdp_md *xdp)
{
	int ret, i;
	__u32 val4 = 0xdeadbeef;
	__u64 val8 = 0xdeadbeefafafcfcf;

#define BENCH_GET(val, size) do { \
		ret = bpf_xdp_trait_set(xdp, 32, val, size, 0);			\
		if (ret != 0)							\
			return ret;						\
		for (i = 0; i < ITERATIONS; i++)				\
			ret = bpf_xdp_trait_get(xdp, 32, val, size);		\
		if (ret != size)						\
			return ret;						\
	} while (0)

	switch (trait_len) {
	case 0:
		BENCH_GET(NULL, 0);
		break;
	case 4:
		BENCH_GET(&val4, sizeof(val4));
		break;
	case 8:
		BENCH_GET(&val8, sizeof(val8));
		break;
	}

	__sync_add_and_fetch(&hits, ITERATIONS);
	return 0;
}

SEC("xdp")
int trait_set(struct xdp_md *xdp)
{
	int ret, i;
	__u32 val4 = 0xdeadbeef;
	__u64 val8 = 0xdeadbeefafafcfcf;

#define BENCH_SET(val, size) do { \
		for (i = 0; i < ITERATIONS; i++)			\
			ret = bpf_xdp_trait_set(xdp, 32, val, size, 0);	\
	} while (0)

	switch (trait_len) {
	case 0:
		BENCH_SET(NULL, 0);
		break;
	case 4:
		BENCH_SET(&val4, sizeof(val4));
		break;
	case 8:
		BENCH_SET(&val8, sizeof(val8));
		break;
	}

	if (ret != 0)
		return ret;

	__sync_add_and_fetch(&hits, ITERATIONS);
	return 0;
}

SEC("xdp")
int trait_move(struct xdp_md *xdp)
{
	int ret, ret_del, i;
	__u32 val4 = 0xdeadbeef;
	__u64 val8 = 0xdeadbeefafafcfcf;

#define BENCH_MOVE(val, size) do { \
		for (i = 0; i < 8; i++)	{						\
			ret = bpf_xdp_trait_set(xdp, 40+i, &val8, sizeof(val8), 0);	\
			if (ret != 0)							\
				return ret;						\
		}									\
		/* We do two operations per iteration, so do half as many to make it
		 * vaguely comparable with other benchmarks
		 */									\
		for (i = 0; i < ITERATIONS/2; i++) {					\
			/* Need to delete after, otherwise we'll just overwrite an
			 * existing trait and there will be nothing to move.
			 */								\
			ret = bpf_xdp_trait_set(xdp, 32, val, size, 0);			\
			ret_del = bpf_xdp_trait_del(xdp, 32);				\
		}									\
	} while (0)

	switch (trait_len) {
	case 0:
		BENCH_MOVE(NULL, 0);
		break;
	case 4:
		BENCH_MOVE(&val4, sizeof(val4));
		break;
	case 8:
		BENCH_MOVE(&val8, sizeof(val8));
		break;
	}

	if (ret != 0)
		return ret;
	if (ret_del != 0)
		return ret_del;

	__sync_add_and_fetch(&hits, ITERATIONS);
	return 0;
}

char _license[] SEC("license") = "GPL";
