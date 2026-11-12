# SPDX-License-Identifier: GPL-2.0
KASAN_SANITIZE_actions-common.o := n
KASAN_SANITIZE_actions-arm.o := n
KASAN_SANITIZE_actions-thumb.o := n
obj-$(CONFIG_KPROBES)		+= core.o actions-common.o checkers-common.o
obj-$(CONFIG_ARM_KPROBES_TEST)	+= test-kprobes-arm.o
test-kprobes-arm-objs		:= test-core.o

ifdef CONFIG_THUMB2_KERNEL
obj-$(CONFIG_KPROBES)		+= actions-thumb.o checkers-thumb.o
test-kprobes-arm-objs		+= test-thumb.o
else
obj-$(CONFIG_KPROBES)		+= actions-arm.o checkers-arm.o
obj-$(CONFIG_OPTPROBES)		+= opt-arm.o
test-kprobes-arm-objs		+= test-arm.o
endif
