# SPDX-License-Identifier: GPL-2.0
# Copyright(c) 2020 Intel Corporation.

# File copied from samples/bpf/Makefile and modified for use

XDPPROGS_PATH ?= $(abspath $(srctree)/$(src))
TOOLS_PATH := $(XDPPROGS_PATH)/../../../../../tools

# List of programs to build
tprogs-y := xdpxceiver

# Libbpf dependencies
LIBBPF = $(TOOLS_PATH)/lib/bpf/libbpf.a

xdpxceiver-objs := xdpxceiver.o

# Tell kbuild to always build the programs
always-y := $(tprogs-y)

ifeq ($(ARCH), arm)
# Strip all except -D__LINUX_ARM_ARCH__ option needed to handle linux
# headers when arm instruction set identification is requested.
ARM_ARCH_SELECTOR := $(filter -D__LINUX_ARM_ARCH__%, $(KBUILD_CFLAGS))
BPF_EXTRA_CFLAGS := $(ARM_ARCH_SELECTOR)
TPROGS_CFLAGS += $(ARM_ARCH_SELECTOR)
endif

TPROGS_CFLAGS += -Wall -O2
TPROGS_CFLAGS += -Wmissing-prototypes
TPROGS_CFLAGS += -Wstrict-prototypes

TPROGS_CFLAGS += -I$(objtree)/usr/include
TPROGS_CFLAGS += -I$(srctree)/tools/testing/selftests/bpf/
TPROGS_CFLAGS += -I$(srctree)/tools/lib/
TPROGS_CFLAGS += -I$(srctree)/tools/include
TPROGS_CFLAGS += -DHAVE_ATTR_TEST=0

ifdef SYSROOT
TPROGS_CFLAGS += --sysroot=$(SYSROOT)
TPROGS_LDFLAGS := -L$(SYSROOT)/usr/lib
endif

TPROGS_LDLIBS += $(LIBBPF) -lelf -lz
TPROGLDLIBS_xdpxceiver += -pthread

# Detect that we're cross compiling and use the cross compiler
ifdef CROSS_COMPILE
CLANG_ARCH_ARGS = --target=$(notdir $(CROSS_COMPILE:%-=%))
endif

# Trick to allow make to be run from this directory
all:
	$(MAKE) -C ../../../../../ M=$(CURDIR) XDPPROGS_PATH=$(CURDIR)

clean:
	$(MAKE) -C ../../../../../ M=$(CURDIR) clean
	@find $(CURDIR) -type f -name '*~' -delete

$(LIBBPF):
# Fix up variables inherited from Kbuild that tools/ build system won't like
	$(MAKE) -C $(dir $@) RM='rm -rf' EXTRA_CFLAGS="$(TPROGS_CFLAGS)" \
		LDFLAGS=$(TPROGS_LDFLAGS) srctree=$(XDPPROGS_PATH)/../../../../../ O=

-include $(XDPPROGS_PATH)/Makefile.target
