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

/* Description
 *	Allocates a local kptr of type represented by 'local_type_id' in program
 *	BTF. User may use the bpf_core_type_id_local macro to pass the type ID
 *	of a struct in program BTF.
 *
 *	The 'local_type_id' parameter must be a known constant.
 *	The 'flags' parameter must be 0.
 * Returns
 *	A local kptr corresponding to passed in 'local_type_id', or NULL on
 *	failure.
 */
void *bpf_kptr_alloc(__u64 local_type_id, __u64 flags) __ksym;

#endif
