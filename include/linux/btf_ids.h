/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_BTF_IDS_H
#define _LINUX_BTF_IDS_H

#include <linux/types.h> /* for u32 */

struct btf_id_set {
	u32 cnt;
	u32 ids[];
};

/* This flag implies BTF_SET8 holds kfunc(s) */
#define BTF_SET8_KFUNCS		(1 << 0)

struct btf_id_set8 {
	u32 cnt;
	u32 flags;
	struct {
		u32 id;
		u32 flags;
	} pairs[];
};

#ifdef CONFIG_DEBUG_INFO_BTF

#include <linux/compiler.h> /* for __PASTE */
#include <linux/compiler_attributes.h> /* for __maybe_unused */
#include <linux/stringify.h>

/*
 * Following macros help to define lists of BTF IDs placed
 * in .BTF_ids section. They are initially filled with zeros
 * (during compilation) and resolved later during the
 * linking phase by resolve_btfids tool.
 *
 * Any change in list layout must be reflected in resolve_btfids
 * tool logic.
 */

#define BTF_IDS_SECTION ".BTF_ids"

#define ____BTF_ID(symbol, word, sec)			\
asm(							\
".pushsection " sec ",\"a\";                   \n"	\
".local " #symbol " ;                          \n"	\
".type  " #symbol ", STT_OBJECT;               \n"	\
".size  " #symbol ", 4;                        \n"	\
#symbol ":                                     \n"	\
".zero 4                                       \n"	\
word							\
".popsection;                                  \n");

#define __BTF_ID(symbol, word) \
	____BTF_ID(symbol, word, BTF_IDS_SECTION)

#define __ID(prefix) \
	__PASTE(__PASTE(prefix, __COUNTER__), __LINE__)

/*
 * The BTF_ID defines unique symbol for each ID pointing
 * to 4 zero bytes.
 */
#define BTF_ID(prefix, name) \
	__BTF_ID(__ID(__BTF_ID__##prefix##__##name##__), "")

#define ____BTF_ID_FLAGS(prefix, name, flags) \
	__BTF_ID(__ID(__BTF_ID__##prefix##__##name##__), ".long " #flags "\n")
#define __BTF_ID_FLAGS(prefix, name, flags, ...) \
	____BTF_ID_FLAGS(prefix, name, flags)
#define BTF_ID_FLAGS(prefix, name, ...) \
	__BTF_ID_FLAGS(prefix, name, ##__VA_ARGS__, 0)

/*
 * The BTF_ID_LIST macro defines pure (unsorted) list
 * of BTF IDs, with following layout:
 *
 * BTF_ID_LIST(list1)
 * BTF_ID(type1, name1)
 * BTF_ID(type2, name2)
 *
 * list1:
 * __BTF_ID__type1__name1__1:
 * .zero 4
 * __BTF_ID__type2__name2__2:
 * .zero 4
 *
 */
#define __BTF_ID_LIST(name, scope, sec)			\
asm(							\
".pushsection " sec ",\"a\";                   \n"	\
"." #scope " " #name ";                        \n"	\
#name ":;                                      \n"	\
".popsection;                                  \n");

#define BTF_ID_LIST(name)				\
__BTF_ID_LIST(name, local, BTF_IDS_SECTION)		\
extern u32 name[];

#define BTF_ID_LIST_GLOBAL(name, n)			\
__BTF_ID_LIST(name, globl, BTF_IDS_SECTION)

/* The BTF_ID_LIST_SINGLE macro defines a BTF_ID_LIST with
 * a single entry.
 */
#define BTF_ID_LIST_SINGLE(name, prefix, typename)	\
	BTF_ID_LIST(name) \
	BTF_ID(prefix, typename)
#define BTF_ID_LIST_GLOBAL_SINGLE(name, prefix, typename) \
	BTF_ID_LIST_GLOBAL(name, 1)			  \
	BTF_ID(prefix, typename)

/*
 * The BTF_ID_UNUSED macro defines 4 zero bytes.
 * It's used when we want to define 'unused' entry
 * in BTF_ID_LIST, like:
 *
 *   BTF_ID_LIST(bpf_skb_output_btf_ids)
 *   BTF_ID(struct, sk_buff)
 *   BTF_ID_UNUSED
 *   BTF_ID(struct, task_struct)
 */

#define BTF_ID_UNUSED					\
asm(							\
".pushsection " BTF_IDS_SECTION ",\"a\";       \n"	\
".zero 4                                       \n"	\
".popsection;                                  \n");

/*
 * The BTF_SET_START/END macros pair defines sorted list of
 * BTF IDs plus its members count, with following layout:
 *
 * BTF_SET_START(list)
 * BTF_ID(type1, name1)
 * BTF_ID(type2, name2)
 * BTF_SET_END(list)
 *
 * __BTF_ID__set__list:
 * .zero 4
 * list:
 * __BTF_ID__type1__name1__3:
 * .zero 4
 * __BTF_ID__type2__name2__4:
 * .zero 4
 *
 */
#define __BTF_SET_START(name, scope)			\
asm(							\
".pushsection " BTF_IDS_SECTION ",\"a\";       \n"	\
"." #scope " __BTF_ID__set__" #name ";         \n"	\
"__BTF_ID__set__" #name ":;                    \n"	\
".zero 4                                       \n"	\
".popsection;                                  \n");

#define BTF_SET_START(name)				\
__BTF_ID_LIST(name, local, BTF_IDS_SECTION)		\
__BTF_SET_START(name, local)

#define BTF_SET_START_GLOBAL(name)			\
__BTF_ID_LIST(name, globl, BTF_IDS_SECTION)		\
__BTF_SET_START(name, globl)

#define BTF_SET_END(name)				\
asm(							\
".pushsection " BTF_IDS_SECTION ",\"a\";      \n"	\
".size __BTF_ID__set__" #name ", .-" #name "  \n"	\
".popsection;                                 \n");	\
extern struct btf_id_set name;

/*
 * BTF_SET_SUB — place a set in .BTF_ids.<name> so vmlinux.lds.h can merge
 * multiple input sections into one output .BTF_ids in a fixed order.
 * <name> must be a single preprocessor token (e.g. bpf_verif_kfunc_arena).
 *
 * Member count: begin is __BTF_ID__setsc__<name> (first in .BTF_ids.<name>);
 * end is linker symbol __BTF_ids_seg_end_<name> (see btf_ids.lds.h). resolve_btfids
 * uses cnt = (end - begin) / 4 - 1.  <name> must not contain "__seg__".
 *
 * extern struct btf_id_set name is emitted by BTF_SET_SUB.  BTF_ID_SUB(name, ...)
 * must use the same <name> as the subsection token.
 */
#define __BTF_IDS_SUBSEC(sub) ".BTF_ids." #sub

/* Indirection so __ID() expands before ____BTF_ID() stringifies its symbol arg. */
#define __BTF_ID_SUB(sym, sec)	____BTF_ID(sym, "", sec)

#define BTF_ID_SUB(sub, prefix, name)				\
	__BTF_ID_SUB(__ID(__BTF_ID__##prefix##__##name##__), __BTF_IDS_SUBSEC(sub))

#define __BTF_ID_LIST_SUB(name, scope)				\
	__BTF_ID_LIST(name, scope, __BTF_IDS_SUBSEC(name))

#define __BTF_SET_SUB(name, scope)				\
asm(								\
".pushsection " __BTF_IDS_SUBSEC(name) ",\"a\";       \n"	\
"." #scope " __BTF_ID__setsc__" #name ";              \n"	\
"__BTF_ID__setsc__" #name ":;                         \n"	\
".zero 4                                              \n"	\
".popsection;                                         \n");

#define BTF_SET_SUB(name)					\
extern struct btf_id_set name;					\
__BTF_ID_LIST_SUB(name, local)					\
__BTF_SET_SUB(name, local)

#include <linux/args.h> /* CONCATENATE, COUNT_ARGS */

/* bpf_verif_kfunc_<sub> (e.g. rbtree_add → bpf_verif_kfunc_rbtree_add) */
#define __BPF_VERIF_KFUNC_SUB(sub) bpf_verif_kfunc_##sub

/* Cascade: emit first subsection, recurse on the rest (same kfunc @name). Up to 6 subs. */
#define __BPF_VERIF_KFUNC_DEF_1(name, s1)				\
	BTF_ID_SUB(__BPF_VERIF_KFUNC_SUB(s1), func, name)

#define __BPF_VERIF_KFUNC_DEF_2(name, s1, s2)				\
	BTF_ID_SUB(__BPF_VERIF_KFUNC_SUB(s1), func, name)		\
	__BPF_VERIF_KFUNC_DEF_1(name, s2)

#define __BPF_VERIF_KFUNC_DEF_3(name, s1, s2, s3)			\
	BTF_ID_SUB(__BPF_VERIF_KFUNC_SUB(s1), func, name)		\
	__BPF_VERIF_KFUNC_DEF_2(name, s2, s3)

#define __BPF_VERIF_KFUNC_DEF_4(name, s1, s2, s3, s4)			\
	BTF_ID_SUB(__BPF_VERIF_KFUNC_SUB(s1), func, name)		\
	__BPF_VERIF_KFUNC_DEF_3(name, s2, s3, s4)

#define __BPF_VERIF_KFUNC_DEF_5(name, s1, s2, s3, s4, s5)		\
	BTF_ID_SUB(__BPF_VERIF_KFUNC_SUB(s1), func, name)		\
	__BPF_VERIF_KFUNC_DEF_4(name, s2, s3, s4, s5)

#define __BPF_VERIF_KFUNC_DEF_6(name, s1, s2, s3, s4, s5, s6)		\
	BTF_ID_SUB(__BPF_VERIF_KFUNC_SUB(s1), func, name)		\
	__BPF_VERIF_KFUNC_DEF_5(name, s2, s3, s4, s5, s6)

/* First arg: kfunc symbol; rest: subsection suffix tokens matching bpf_verif_kfunc_<s>. */
#define BPF_VERIF_KFUNC_DEF(name, ...)					\
	CONCATENATE(__BPF_VERIF_KFUNC_DEF_, COUNT_ARGS(__VA_ARGS__))(name, __VA_ARGS__)

/*
 * The BTF_SET8_START/END macros pair defines sorted list of
 * BTF IDs and their flags plus its members count, with the
 * following layout:
 *
 * BTF_SET8_START(list)
 * BTF_ID_FLAGS(type1, name1, flags)
 * BTF_ID_FLAGS(type2, name2, flags)
 * BTF_SET8_END(list)
 *
 * __BTF_ID__set8__list:
 * .zero 8
 * list:
 * __BTF_ID__type1__name1__3:
 * .zero 4
 * .word (1 << 0) | (1 << 2)
 * __BTF_ID__type2__name2__5:
 * .zero 4
 * .word (1 << 3) | (1 << 1) | (1 << 2)
 *
 */
#define __BTF_SET8_START(name, scope, flags)		\
__BTF_ID_LIST(name, local, BTF_IDS_SECTION)		\
asm(							\
".pushsection " BTF_IDS_SECTION ",\"a\";       \n"	\
"." #scope " __BTF_ID__set8__" #name ";        \n"	\
"__BTF_ID__set8__" #name ":;                   \n"	\
".zero 4                                       \n"	\
".long " __stringify(flags)                   "\n"	\
".popsection;                                  \n");

#define BTF_SET8_START(name)				\
__BTF_SET8_START(name, local, 0)

#define BTF_SET8_END(name)				\
asm(							\
".pushsection " BTF_IDS_SECTION ",\"a\";      \n"	\
".size __BTF_ID__set8__" #name ", .-" #name "  \n"	\
".popsection;                                 \n");	\
extern struct btf_id_set8 name;

#define BTF_KFUNCS_START(name)				\
__BTF_SET8_START(name, local, BTF_SET8_KFUNCS)

#define BTF_KFUNCS_END(name)				\
BTF_SET8_END(name)

#else

#define BTF_ID_LIST(name) static u32 __maybe_unused name[128];
#define BTF_ID(prefix, name)
#define BTF_ID_FLAGS(prefix, name, ...)
#define BTF_ID_UNUSED
#define BTF_ID_LIST_GLOBAL(name, n) u32 __maybe_unused name[n];
#define BTF_ID_LIST_SINGLE(name, prefix, typename) static u32 __maybe_unused name[1];
#define BTF_ID_LIST_GLOBAL_SINGLE(name, prefix, typename) u32 __maybe_unused name[1];
#define BTF_SET_START(name) static struct btf_id_set __maybe_unused name = { 0 };
#define BTF_SET_START_GLOBAL(name) static struct btf_id_set __maybe_unused name = { 0 };
#define BTF_SET_END(name)
#define BTF_SET_SUB(name) static struct btf_id_set __maybe_unused name = { 0 };
#define BTF_ID_SUB(sub, prefix, name)
#define BPF_VERIF_KFUNC_DEF(name, ...)
#define BTF_SET8_START(name) static struct btf_id_set8 __maybe_unused name = { 0 };
#define BTF_SET8_END(name)
#define BTF_KFUNCS_START(name) static struct btf_id_set8 __maybe_unused name = { .flags = BTF_SET8_KFUNCS };
#define BTF_KFUNCS_END(name)

#endif /* CONFIG_DEBUG_INFO_BTF */

#ifdef CONFIG_NET
/* Define a list of socket types which can be the argument for
 * skc_to_*_sock() helpers. All these sockets should have
 * sock_common as the first argument in its memory layout.
 */
#define BTF_SOCK_TYPE_xxx \
	BTF_SOCK_TYPE(BTF_SOCK_TYPE_INET, inet_sock)			\
	BTF_SOCK_TYPE(BTF_SOCK_TYPE_INET_CONN, inet_connection_sock)	\
	BTF_SOCK_TYPE(BTF_SOCK_TYPE_INET_REQ, inet_request_sock)	\
	BTF_SOCK_TYPE(BTF_SOCK_TYPE_INET_TW, inet_timewait_sock)	\
	BTF_SOCK_TYPE(BTF_SOCK_TYPE_REQ, request_sock)			\
	BTF_SOCK_TYPE(BTF_SOCK_TYPE_SOCK, sock)				\
	BTF_SOCK_TYPE(BTF_SOCK_TYPE_SOCK_COMMON, sock_common)		\
	BTF_SOCK_TYPE(BTF_SOCK_TYPE_TCP, tcp_sock)			\
	BTF_SOCK_TYPE(BTF_SOCK_TYPE_TCP_REQ, tcp_request_sock)		\
	BTF_SOCK_TYPE(BTF_SOCK_TYPE_TCP_TW, tcp_timewait_sock)		\
	BTF_SOCK_TYPE(BTF_SOCK_TYPE_TCP6, tcp6_sock)			\
	BTF_SOCK_TYPE(BTF_SOCK_TYPE_UDP, udp_sock)			\
	BTF_SOCK_TYPE(BTF_SOCK_TYPE_UDP6, udp6_sock)			\
	BTF_SOCK_TYPE(BTF_SOCK_TYPE_UNIX, unix_sock)			\
	BTF_SOCK_TYPE(BTF_SOCK_TYPE_MPTCP, mptcp_sock)			\
	BTF_SOCK_TYPE(BTF_SOCK_TYPE_SOCKET, socket)

enum {
#define BTF_SOCK_TYPE(name, str) name,
BTF_SOCK_TYPE_xxx
#undef BTF_SOCK_TYPE
MAX_BTF_SOCK_TYPE,
};

extern u32 btf_sock_ids[];
#endif

#define BTF_TRACING_TYPE_xxx	\
	BTF_TRACING_TYPE(BTF_TRACING_TYPE_TASK, task_struct)	\
	BTF_TRACING_TYPE(BTF_TRACING_TYPE_FILE, file)		\
	BTF_TRACING_TYPE(BTF_TRACING_TYPE_VMA, vm_area_struct)

enum {
#define BTF_TRACING_TYPE(name, type) name,
BTF_TRACING_TYPE_xxx
#undef BTF_TRACING_TYPE
MAX_BTF_TRACING_TYPE,
};

extern u32 btf_tracing_ids[];
extern u32 bpf_cgroup_btf_id[];
extern u32 bpf_local_storage_map_btf_id[];
extern u32 btf_bpf_map_id[];
extern u32 bpf_kmem_cache_btf_id[];

#endif
