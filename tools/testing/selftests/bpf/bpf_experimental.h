#ifndef __KERNEL__

#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

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
 *	The 'local_type_id' parameter must be a known constant. The 'flags'
 *	parameter must be 0.
 *
 *	The 'meta__ign' parameter is a hidden argument that is ignored.
 * Returns
 *	A local kptr corresponding to passed in 'local_type_id', or NULL on
 *	failure.
 */
extern void *bpf_kptr_new_impl(__u64 local_type_id, __u64 flags, void *meta__ign) __ksym;

/* Convenience macro to wrap over bpf_kptr_new_impl */
#define bpf_kptr_new(type) bpf_kptr_new_impl(bpf_core_type_id_local(type), 0, NULL)

/* Description
 *	Free a local kptr. All fields of local kptr that require destruction
 *	will be destructed before the storage is freed.
 *
 *	The 'meta__ign' parameter is a hidden argument that is ignored.
 * Returns
 *	Void.
 */
extern void bpf_kptr_drop_impl(void *kptr, void *meta__ign) __ksym;

/* Convenience macro to wrap over bpf_kptr_drop_impl */
#define bpf_kptr_drop(kptr) bpf_kptr_drop_impl(kptr, NULL)

#endif
