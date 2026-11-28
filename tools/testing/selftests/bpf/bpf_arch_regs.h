/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BPF_ARCH_REGS_H
#define __BPF_ARCH_REGS_H

/* How many arguments are passed to function in register */
#if defined(__TARGET_ARCH_x86) || defined(__x86_64__)
#define FUNC_REG_ARG_CNT 6
#elif defined(__i386__)
#define FUNC_REG_ARG_CNT 3
#elif defined(__TARGET_ARCH_s390) || defined(__s390x__)
#define FUNC_REG_ARG_CNT 5
#elif defined(__TARGET_ARCH_arm) || defined(__arm__)
#define FUNC_REG_ARG_CNT 4
#elif defined(__TARGET_ARCH_arm64) || defined(__aarch64__)
#define FUNC_REG_ARG_CNT 8
#elif defined(__TARGET_ARCH_mips) || defined(__mips__)
#define FUNC_REG_ARG_CNT 8
#elif defined(__TARGET_ARCH_powerpc) || defined(__powerpc__) || defined(__powerpc64__)
#define FUNC_REG_ARG_CNT 8
#elif defined(__TARGET_ARCH_sparc) || defined(__sparc__)
#define FUNC_REG_ARG_CNT 6
#elif defined(__TARGET_ARCH_riscv) || defined(__riscv__)
#define FUNC_REG_ARG_CNT 8
#else
/* default to 5 for others */
#define FUNC_REG_ARG_CNT 5
#endif

#endif /* __BPF_ARCH_REGS_H */
