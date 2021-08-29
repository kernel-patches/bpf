# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the Linux BPFILTER layer.
#

LIBBPF_SRCS = $(srctree)/tools/lib/bpf/
LIBBPF_A = $(obj)/libbpf.a
LIBBPF_OUT = $(abspath $(obj))

$(LIBBPF_A):
	$(Q)$(MAKE) -C $(LIBBPF_SRCS) O=$(LIBBPF_OUT)/ OUTPUT=$(LIBBPF_OUT)/ $(LIBBPF_OUT)/libbpf.a

userprogs := bpfilter_umh
bpfilter_umh-objs := main.o map-common.o codegen.o context.o match.o target.o rule.o table.o
bpfilter_umh-objs += sockopt.o filter-table.o
bpfilter_umh-objs += xt_udp.o
bpfilter_umh-userldlibs := $(LIBBPF_A) -lelf -lz
userccflags += -I $(srctree)/tools/include/ -I $(srctree)/tools/include/uapi -I $(srctree)/tools/lib

$(obj)/bpfilter_umh: $(LIBBPF_A)

ifeq ($(CONFIG_BPFILTER_UMH), y)
# builtin bpfilter_umh should be linked with -static
# since rootfs isn't mounted at the time of __init
# function is called and do_execv won't find elf interpreter
userldflags += -static
endif

$(obj)/bpfilter_umh_blob.o: $(obj)/bpfilter_umh

obj-$(CONFIG_BPFILTER_UMH) += bpfilter.o
bpfilter-objs += bpfilter_kern.o bpfilter_umh_blob.o
