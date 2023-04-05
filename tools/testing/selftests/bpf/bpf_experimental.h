#ifndef __BPF_EXPERIMENTAL__
#define __BPF_EXPERIMENTAL__

#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define __contains(name, node) __attribute__((btf_decl_tag("contains:" #name ":" #node)))

/* Description
 *	Allocates an object of the type represented by 'local_type_id' in
 *	program BTF. User may use the bpf_core_type_id_local macro to pass the
 *	type ID of a struct in program BTF.
 *
 *	The 'local_type_id' parameter must be a known constant.
 *	The 'meta' parameter is a hidden argument that is ignored.
 * Returns
 *	A pointer to an object of the type corresponding to the passed in
 *	'local_type_id', or NULL on failure.
 */
extern void *bpf_obj_new_impl(__u64 local_type_id, void *meta) __ksym;

/* Convenience macro to wrap over bpf_obj_new_impl */
#define bpf_obj_new(type) ((type *)bpf_obj_new_impl(bpf_core_type_id_local(type), NULL))

/* Description
 *	Free an allocated object. All fields of the object that require
 *	destruction will be destructed before the storage is freed.
 *
 *	The 'meta' parameter is a hidden argument that is ignored.
 * Returns
 *	Void.
 */
extern void bpf_obj_drop_impl(void *kptr, void *meta) __ksym;

/* Convenience macro to wrap over bpf_obj_drop_impl */
#define bpf_obj_drop(kptr) bpf_obj_drop_impl(kptr, NULL)

/* Description
 *	Add a new entry to the beginning of the BPF linked list.
 * Returns
 *	Void.
 */
extern void bpf_list_push_front(struct bpf_list_head *head, struct bpf_list_node *node) __ksym;

/* Description
 *	Add a new entry to the end of the BPF linked list.
 * Returns
 *	Void.
 */
extern void bpf_list_push_back(struct bpf_list_head *head, struct bpf_list_node *node) __ksym;

/* Description
 *	Remove the entry at the beginning of the BPF linked list.
 * Returns
 *	Pointer to bpf_list_node of deleted entry, or NULL if list is empty.
 */
extern struct bpf_list_node *bpf_list_pop_front(struct bpf_list_head *head) __ksym;

/* Description
 *	Remove the entry at the end of the BPF linked list.
 * Returns
 *	Pointer to bpf_list_node of deleted entry, or NULL if list is empty.
 */
extern struct bpf_list_node *bpf_list_pop_back(struct bpf_list_head *head) __ksym;

/* Description
 *	Remove 'node' from rbtree with root 'root'
 * Returns
 * 	Pointer to the removed node, or NULL if 'root' didn't contain 'node'
 */
extern struct bpf_rb_node *bpf_rbtree_remove(struct bpf_rb_root *root,
					     struct bpf_rb_node *node) __ksym;

/* Description
 *	Add 'node' to rbtree with root 'root' using comparator 'less'
 * Returns
 *	Nothing
 */
extern void bpf_rbtree_add(struct bpf_rb_root *root, struct bpf_rb_node *node,
			   bool (less)(struct bpf_rb_node *a, const struct bpf_rb_node *b)) __ksym;

/* Description
 *	Return the first (leftmost) node in input tree
 * Returns
 *	Pointer to the node, which is _not_ removed from the tree. If the tree
 *	contains no nodes, returns NULL.
 */
extern struct bpf_rb_node *bpf_rbtree_first(struct bpf_rb_root *root) __ksym;

/* Description
 *  Throw an exception, terminating the execution of the program immediately.
 *  The eBPF runtime unwinds the stack automatically and exits the program with
 *  the default return value of 0.
 * Returns
 *  This function never returns.
 */
extern void bpf_throw(void) __attribute__((noreturn)) __ksym;

/*
 * Description
 *  Set the callback which will be invoked after an exception is thrown and the
 *  eBPF runtime has completely unwinded the program stack. The return value of
 *  this callback is treated as the return value of the program when the
 *  exception is thrown.
 * Returns
 *  Void
 */
extern void bpf_set_exception_callback(int (*)(void)) __ksym;

#define __bpf_assert_op(LHS, op, RHS)								   \
	_Static_assert(sizeof(&(LHS)), "1st argument must be an lvalue expression");		   \
	_Static_assert(__builtin_constant_p((RHS)), "2nd argument must be a constant expression"); \
	asm volatile ("if %[lhs] " op " %[rhs] goto +1; call bpf_throw"				   \
		      : : [lhs] "r"(LHS) , [rhs] "i"(RHS) :)

#define bpf_assert_eq(LHS, RHS) __bpf_assert_op(LHS, "==", RHS)
#define bpf_assert_ne(LHS, RHS) __bpf_assert_op(LHS, "!=", RHS)
#define bpf_assert_lt(LHS, RHS) __bpf_assert_op(LHS, "<", RHS)
#define bpf_assert_gt(LHS, RHS) __bpf_assert_op(LHS, ">", RHS)
#define bpf_assert_le(LHS, RHS) __bpf_assert_op(LHS, "<=", RHS)
#define bpf_assert_ge(LHS, RHS) __bpf_assert_op(LHS, ">=", RHS)
#define bpf_assert_slt(LHS, RHS) __bpf_assert_op(LHS, "s<", RHS)
#define bpf_assert_sgt(LHS, RHS) __bpf_assert_op(LHS, "s>", RHS)
#define bpf_assert_sle(LHS, RHS) __bpf_assert_op(LHS, "s<=", RHS)
#define bpf_assert_sge(LHS, RHS) __bpf_assert_op(LHS, "s>=", RHS)

#endif
