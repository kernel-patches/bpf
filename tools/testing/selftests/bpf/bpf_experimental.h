#ifndef __KERNEL__

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

#define __contains(kind, name, node) __attribute__((btf_decl_tag("contains:" #kind ":" #name ":" #node)))
#define __kernel __attribute__((btf_decl_tag("kernel")))
#define __local __attribute__((btf_type_tag("local")))

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

/* Description
 *	Initialize bpf_list_node field in a local kptr. This kfunc has
 *	constructor semantics, and thus can only be called on a local kptr in
 *	'constructing' phase.
 * Returns
 *	Void.
 */
void bpf_list_node_init(struct bpf_list_node *node) __ksym;

/* Description
 *	Initialize bpf_spin_lock field in a local kptr. This kfunc has
 *	constructor semantics, and thus can only be called on a local kptr in
 *	'constructing' phase.
 * Returns
 *	Void.
 */
void bpf_spin_lock_init(struct bpf_spin_lock *node) __ksym;

/* Description
 *	Initialize bpf_list_head field in a local kptr. This kfunc has
 *	constructor semantics, and thus can only be called on a local kptr in
 *	'constructing' phase.
 * Returns
 *	Void.
 */
void bpf_list_head_init(struct bpf_list_head *node) __ksym;

/* Description
 *	Free a local kptr. All fields of local kptr that require destruction
 *	need to be in destructed state before this call is made.
 * Returns
 *	Void.
 */
void bpf_kptr_free(void *kptr) __ksym;

/* Description
 *	Add a new entry to the head of a BPF linked list.
 * Returns
 *	Void.
 */
void bpf_list_add(struct bpf_list_node *node, struct bpf_list_head *head) __ksym;

/* Description
 *	Add a new entry to the tail of a BPF linked list.
 * Returns
 *	Void.
 */
void bpf_list_add_tail(struct bpf_list_node *node, struct bpf_list_head *head) __ksym;

/* Description
 *	Remove an entry already part of a BPF linked list.
 * Returns
 *	Void.
 */
void bpf_list_del(struct bpf_list_node *node) __ksym;

/* Description
 *	Remove the first entry of a BPF linked list.
 * Returns
 *	Pointer to bpf_list_node of deleted entry, or NULL if list is empty.
 */
struct bpf_list_node *bpf_list_pop_front(struct bpf_list_head *head) __ksym;

/* Description
 *	Remove the last entry of a BPF linked list.
 * Returns
 *	Pointer to bpf_list_node of deleted entry, or NULL if list is empty.
 */
struct bpf_list_node *bpf_list_pop_back(struct bpf_list_head *head) __ksym;

/* Description
 *	Destruct bpf_list_head field in a local kptr. This kfunc has destructor
 *	semantics, and marks local kptr as destructing if it isn't already.
 *
 *	Note that value_node_offset is the offset of bpf_list_node inside the
 *	value type of local kptr's bpf_list_head. It must be a known constant.
 * Returns
 *	Void.
 */
void bpf_list_head_fini(struct bpf_list_head *node, u64 value_node_offset) __ksym;

#endif
