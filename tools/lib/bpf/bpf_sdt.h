/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/*
 * USDT-like probe for BPF programs.
 *
 * 1. Example
 *
 * A probe in the target program can be declared and defined like:
 *
 *   BPF_SDT_DECLARE2(my_trace, int, int);
 *
 *   SEC("xdp")
 *   int xdp_prog(struct xdp_md *ctx)
 *   {
 *       int len = ctx->data_end - ctx->data;
 *       int ret = XDP_DROP;
 *       ...
 *       BPF_SDT_PROBE2(my_trace, len, ret);
 *       ...
 *   }
 *
 * An observer would be like:
 *
 *   SEC("bpf_sdt")
 *   int BPF_PROG(observer_prog, int len, int ret)
 *   {
 *       bpf_printk("len=%d ret=%d\n", len, ret);
 *       return 0;
 *   }
 *
 * The target program and probe site is set at attach time dynamically.
 *
 * 2. Design
 *
 * 2.1 declaration macro
 *
 * BPF_SDT_DECLARE<N>(name, types...) generates:
 *
 *  - A BTF function-pointer variable in a .debug_* section:
 *
 *       static void (*const __sdt_type_##name)(types...);
 *
 *   which produces a BTF VAR -> PTR -> FUNC_PROTO(types...) chain
 *   tagged with btf_decl_tag("bpf_sdt:<name>:<nargs>"). The BPF
 *   linker discards the .debug_* section but preserves the BTF
 *   entries, so the argument types survive into the final object.
 *   The type will be passed to the kernel for the verifier to check
 *   if it matches the real value type in the argument register.
 *
 *  - One dummy static variable per argument:
 *
 *       __attribute__((section(".debug_bpf_sdt_chk")))
 *       typeof(declared_type) __sdt_chk_##name##_N;
 *
 *   The dummy variable carries the declared type. At the
 *   BPF_SDT_PROBE call site, _Static_assert with
 *   __builtin_types_compatible_p() compares the caller's actual
 *   argument type against the dummy variable's type:
 *
 *       _Static_assert(__builtin_types_compatible_p(
 *                       typeof(caller_arg),
 *                       typeof(__sdt_chk_##name##_N)),
 *                       "type mismatch");
 *
 *   For example, if the caller passes an int where the declaration
 *   said char *, the compiler fails with a message naming the
 *   mismatched argument.
 *
 * 2.2 probe macro
 *
 * BPF_SDT_PROBE<N> is an inline assembly sequence that emits into two
 * ELF sections simultaneously. A goto+0 instruction is inserted at the
 * call site in the bpf prog code section. It works as a NOP, and will be
 * patched to a jump instruction when an observer is attached. The call
 * site address and argument information are recorded into a separate
 * section .bpf_sdt_notes. This section is not executed, it is used as
 * metadata. libbpf will convert the metadata to an insn_array map at
 * load time.
 *
 * An interesting note is that the argument registers are recorded in
 * BPF move instructions, like r1 = %[arg_reg0]. The instruction is not
 * executed, it is only used by the linker to extract the argument
 * register from the src_reg.
 *
 * For BPF_SDT_PROBE2(my_trace, len, ret) the compiler produces:
 *
 * [code section, e.g. xdp]
 *     goto +0                  // NOP, patched to CALL at attach time
 *
 * [.bpf_sdt_notes]
 *     ___sdt_jt_my_trace:      // symbol marking this entry's boundary
 *     .quad  0b                // 8 bytes: offset of the NOP in the code
 *                              // section (resolved by the linker via
 *                              // R_BPF_64_ABS64 relocation)
 *     r1 = %[arg1_reg]         // 8 bytes per argument: BPF move instruction
 *                              // whose src_reg field encodes the BPF
 *                              // register holding each probe argument
 *     r2 = %[arg2_reg]
 *
 *     ....
 *
 *  [.BTF]
 *     FUNC_PROTO (int, int) -> void   // from BPF_SDT_DECLARE2 stub
 *     DECL_TAG "bpf_sdt:my_trace:2"   // keyed by name + nargs
 */

#ifndef __BPF_SDT_PROBE_H
#define __BPF_SDT_PROBE_H

#define ___sdt_decl_attr(name, nargs)					\
	__attribute__((used, section(".debug_bpf_sdt_types"),		\
			btf_decl_tag("bpf_sdt:" #name ":" #nargs)))

#define ___sdt_chk_attr							\
	 __attribute__((unused, section(".debug_bpf_sdt_chk")))

#define BPF_SDT_DECLARE(name)						\
	___sdt_decl_attr(name, 0)					\
	static void (*const __sdt_type_##name)(void)

#define BPF_SDT_DECLARE1(name, t0)					\
	___sdt_decl_attr(name, 1)					\
	static void (*const __sdt_type_##name)(t0);			\
	___sdt_chk_attr t0 __sdt_chk_##name##_0

#define BPF_SDT_DECLARE2(name, t0, t1)					\
	___sdt_decl_attr(name, 2)					\
	static void (*const __sdt_type_##name)(t0, t1);			\
	___sdt_chk_attr t0 __sdt_chk_##name##_0;			\
	___sdt_chk_attr t1 __sdt_chk_##name##_1

#define BPF_SDT_DECLARE3(name, t0, t1, t2)				\
	___sdt_decl_attr(name, 3)					\
	static void (*const __sdt_type_##name)(t0, t1, t2);		\
	___sdt_chk_attr t0 __sdt_chk_##name##_0;			\
	___sdt_chk_attr t1 __sdt_chk_##name##_1;			\
	___sdt_chk_attr t2 __sdt_chk_##name##_2

#define BPF_SDT_DECLARE4(name, t0, t1, t2, t3)				\
	___sdt_decl_attr(name, 4)					\
	static void (*const __sdt_type_##name)(t0, t1, t2, t3);		\
	___sdt_chk_attr t0 __sdt_chk_##name##_0;			\
	___sdt_chk_attr t1 __sdt_chk_##name##_1;			\
	___sdt_chk_attr t2 __sdt_chk_##name##_2;			\
	___sdt_chk_attr t3 __sdt_chk_##name##_3

#define BPF_SDT_DECLARE5(name, t0, t1, t2, t3, t4)			\
	___sdt_decl_attr(name, 5)					\
	static void (*const __sdt_type_##name)(t0, t1, t2, t3, t4);	\
	___sdt_chk_attr t0 __sdt_chk_##name##_0;			\
	___sdt_chk_attr t1 __sdt_chk_##name##_1;			\
	___sdt_chk_attr t2 __sdt_chk_##name##_2;			\
	___sdt_chk_attr t3 __sdt_chk_##name##_3;			\
	___sdt_chk_attr t4 __sdt_chk_##name##_4

/* probe macros, 0-5 arguments
 *
 * Each probe emits a NOP (goto +0) in the program stream plus a
 * .bpf_sdt_notes entry.  The entry begins with the ___sdt_jt_<name>
 * label so that libbpf can locate each entry boundary at load time.
 * One BPF_SDT_PROBE<N> invocation per probe name is required; invoking
 * the same name twice produces a duplicate symbol.
 */
#define BPF_SDT_PROBE(name)						\
({									\
	asm volatile(							\
		"0:\n"							\
		"goto +0\n"						\
		".pushsection .bpf_sdt_notes,\"\",@progbits\n"		\
		"___sdt_jt_" #name ":\n"				\
		".quad 0b\n"						\
		".popsection\n"						\
	);								\
})

#define BPF_SDT_PROBE1(name, a)						\
({									\
	_Static_assert(__builtin_types_compatible_p(typeof(a),		\
			typeof(__sdt_chk_##name##_0)),			\
			"BPF_SDT_PROBE1: arg0 type mismatch");		\
	_Static_assert(sizeof(typeof(a)) <= 8,				\
			"BPF_SDT_PROBE1: arg0 too large, use pointer");	\
	typeof(a) __a0 = (a);						\
	asm volatile(							\
		"0:\n"							\
		"goto +0\n"						\
		".pushsection .bpf_sdt_notes,\"\",@progbits\n"		\
		"___sdt_jt_" #name ":\n"				\
		".quad 0b\n"						\
		"r1 = %0\n"						\
		".popsection\n"						\
		:: "r"(__a0)						\
	);								\
})

#define BPF_SDT_PROBE2(name, a, b)					\
({									\
	_Static_assert(__builtin_types_compatible_p(typeof(a),		\
			typeof(__sdt_chk_##name##_0)),			\
			"BPF_SDT_PROBE2: arg0 type mismatch");		\
	_Static_assert(sizeof(typeof(a)) <= 8,				\
			"BPF_SDT_PROBE2: arg0 too large, use pointer");	\
	_Static_assert(__builtin_types_compatible_p(typeof(b),		\
			typeof(__sdt_chk_##name##_1)),			\
			"BPF_SDT_PROBE2: arg1 type mismatch");		\
	_Static_assert(sizeof(typeof(b)) <= 8,				\
			"BPF_SDT_PROBE2: arg1 too large, use pointer");	\
	typeof(a) __a0 = (a);						\
	typeof(b) __a1 = (b);						\
	asm volatile(							\
		"0:\n"							\
		"goto +0\n"						\
		".pushsection .bpf_sdt_notes,\"\",@progbits\n"		\
		"___sdt_jt_" #name ":\n"				\
		".quad 0b\n"						\
		"r1 = %0\n"						\
		"r2 = %1\n"						\
		".popsection\n"						\
		:: "r"(__a0), "r"(__a1)					\
	);								\
})

#define BPF_SDT_PROBE3(name, a, b, c)					\
({									\
	_Static_assert(__builtin_types_compatible_p(typeof(a),		\
			typeof(__sdt_chk_##name##_0)),			\
			"BPF_SDT_PROBE3: arg0 type mismatch");		\
	_Static_assert(sizeof(typeof(a)) <= 8,				\
			"BPF_SDT_PROBE3: arg0 too large, use pointer");	\
	_Static_assert(__builtin_types_compatible_p(typeof(b),		\
			typeof(__sdt_chk_##name##_1)),			\
			"BPF_SDT_PROBE3: arg1 type mismatch");		\
	_Static_assert(sizeof(typeof(b)) <= 8,				\
			"BPF_SDT_PROBE3: arg1 too large, use pointer");	\
	_Static_assert(__builtin_types_compatible_p(typeof(c),		\
			typeof(__sdt_chk_##name##_2)),			\
			"BPF_SDT_PROBE3: arg2 type mismatch");		\
	_Static_assert(sizeof(typeof(c)) <= 8,				\
			"BPF_SDT_PROBE3: arg2 too large, use pointer");	\
	typeof(a) __a0 = (a);						\
	typeof(b) __a1 = (b);						\
	typeof(c) __a2 = (c);						\
	asm volatile(							\
		"0:\n"							\
		"goto +0\n"						\
		".pushsection .bpf_sdt_notes,\"\",@progbits\n"		\
		"___sdt_jt_" #name ":\n"				\
		".quad 0b\n"						\
		"r1 = %0\n"						\
		"r2 = %1\n"						\
		"r3 = %2\n"						\
		".popsection\n"						\
		:: "r"(__a0), "r"(__a1), "r"(__a2)			\
	);								\
})

#define BPF_SDT_PROBE4(name, a, b, c, d)				\
({									\
	_Static_assert(__builtin_types_compatible_p(typeof(a),		\
			typeof(__sdt_chk_##name##_0)),			\
			"BPF_SDT_PROBE4: arg0 type mismatch");		\
	_Static_assert(sizeof(typeof(a)) <= 8,				\
			"BPF_SDT_PROBE4: arg0 too large, use pointer");	\
	_Static_assert(__builtin_types_compatible_p(typeof(b),		\
			typeof(__sdt_chk_##name##_1)),			\
			"BPF_SDT_PROBE4: arg1 type mismatch");		\
	_Static_assert(sizeof(typeof(b)) <= 8,				\
			"BPF_SDT_PROBE4: arg1 too large, use pointer");	\
	_Static_assert(__builtin_types_compatible_p(typeof(c),		\
			typeof(__sdt_chk_##name##_2)),			\
			"BPF_SDT_PROBE4: arg2 type mismatch");		\
	_Static_assert(sizeof(typeof(c)) <= 8,				\
			"BPF_SDT_PROBE4: arg2 too large, use pointer");	\
	_Static_assert(__builtin_types_compatible_p(typeof(d),		\
			typeof(__sdt_chk_##name##_3)),			\
			"BPF_SDT_PROBE4: arg3 type mismatch");		\
	_Static_assert(sizeof(typeof(d)) <= 8,				\
			"BPF_SDT_PROBE4: arg3 too large, use pointer");	\
	typeof(a) __a0 = (a);						\
	typeof(b) __a1 = (b);						\
	typeof(c) __a2 = (c);						\
	typeof(d) __a3 = (d);						\
	asm volatile(							\
		"0:\n"							\
		"goto +0\n"						\
		".pushsection .bpf_sdt_notes,\"\",@progbits\n"		\
		"___sdt_jt_" #name ":\n"				\
		".quad 0b\n"						\
		"r1 = %0\n"						\
		"r2 = %1\n"						\
		"r3 = %2\n"						\
		"r4 = %3\n"						\
		".popsection\n"						\
		:: "r"(__a0), "r"(__a1), "r"(__a2), "r"(__a3)		\
	);								\
})

#define BPF_SDT_PROBE5(name, a, b, c, d, e)				\
({									\
	_Static_assert(__builtin_types_compatible_p(typeof(a),		\
			typeof(__sdt_chk_##name##_0)),			\
			"BPF_SDT_PROBE5: arg0 type mismatch");		\
	_Static_assert(sizeof(typeof(a)) <= 8,				\
			"BPF_SDT_PROBE5: arg0 too large, use pointer");	\
	_Static_assert(__builtin_types_compatible_p(typeof(b),		\
			typeof(__sdt_chk_##name##_1)),			\
			"BPF_SDT_PROBE5: arg1 type mismatch");		\
	_Static_assert(sizeof(typeof(b)) <= 8,				\
			"BPF_SDT_PROBE5: arg1 too large, use pointer");	\
	_Static_assert(__builtin_types_compatible_p(typeof(c),		\
			typeof(__sdt_chk_##name##_2)),			\
			"BPF_SDT_PROBE5: arg2 type mismatch");		\
	_Static_assert(sizeof(typeof(c)) <= 8,				\
			"BPF_SDT_PROBE5: arg2 too large, use pointer");	\
	_Static_assert(__builtin_types_compatible_p(typeof(d),		\
			typeof(__sdt_chk_##name##_3)),			\
			"BPF_SDT_PROBE5: arg3 type mismatch");		\
	_Static_assert(sizeof(typeof(d)) <= 8,				\
			"BPF_SDT_PROBE5: arg3 too large, use pointer");	\
	_Static_assert(__builtin_types_compatible_p(typeof(e),		\
			typeof(__sdt_chk_##name##_4)),			\
			"BPF_SDT_PROBE5: arg4 type mismatch");		\
	_Static_assert(sizeof(typeof(e)) <= 8,				\
			"BPF_SDT_PROBE5: arg4 too large, use pointer");	\
	typeof(a) __a0 = (a);						\
	typeof(b) __a1 = (b);						\
	typeof(c) __a2 = (c);						\
	typeof(d) __a3 = (d);						\
	typeof(e) __a4 = (e);						\
	asm volatile(							\
		"0:\n"							\
		"goto +0\n"						\
		".pushsection .bpf_sdt_notes,\"\",@progbits\n"		\
		"___sdt_jt_" #name ":\n"				\
		".quad 0b\n"						\
		"r1 = %0\n"						\
		"r2 = %1\n"						\
		"r3 = %2\n"						\
		"r4 = %3\n"						\
		"r5 = %4\n"						\
		".popsection\n"						\
		:: "r"(__a0), "r"(__a1), "r"(__a2), "r"(__a3), "r"(__a4)\
	);								\
})

#endif /* __BPF_SDT_PROBE_H */
