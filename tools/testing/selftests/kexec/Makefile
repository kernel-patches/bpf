# SPDX-License-Identifier: GPL-2.0-only
# Makefile for kexec tests

top_srcdir = ../../../..
include $(top_srcdir)/scripts/subarch.include
ARCH_PROCESSED := $(shell echo $(or $(ARCH),$(SUBARCH)) | sed -e s/i.86/x86/ -e s/x86_64/x86/)

PROBE_CC = $(filter-out -fuse-ld=%,$(CC)) $(CFLAGS) $(USERCFLAGS) -E -P -x c -
CC_IS_64BIT = $(shell echo __SIZEOF_LONG__ | $(PROBE_CC) || echo 8)
PPC64LE = $(shell printf '\043if defined(__powerpc64__) && __BYTE_ORDER__ == \
	__ORDER_LITTLE_ENDIAN__\n1\n\043endif\n' | $(PROBE_CC))

ifeq ($(ARCH_PROCESSED),x86)
TEST_PROGS = test_kexec_load.sh test_kexec_file_load.sh \
	$(if $(filter 8,$(CC_IS_64BIT)),test_kexec_jump.sh)
TEST_GEN_PROGS = $(if $(filter 8,$(CC_IS_64BIT)),test_kexec_jump)
else ifneq (,$(filter powerpc ppc64le,$(ARCH_PROCESSED)))
TEST_PROGS = $(if $(filter 1,$(PPC64LE)),test_kexec_load.sh test_kexec_file_load.sh)
endif
TEST_FILES = $(if $(TEST_PROGS),kexec_common_lib.sh)

include ../lib.mk
