#ifndef __KERNEL__

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

#else

struct bpf_list_head {
	__u64 __a;
	__u64 __b;
} __attribute__((aligned(8)));

struct bpf_list_node {
	__u64 __a;
	__u64 __b;
} __attribute__((aligned(8)));

#endif

#ifndef __KERNEL__
#endif
