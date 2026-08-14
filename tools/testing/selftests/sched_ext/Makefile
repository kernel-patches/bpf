# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
include ../../../build/Build.include
include ../../../scripts/Makefile.arch
include ../../../scripts/Makefile.include

TEST_GEN_PROGS := runner

# override lib.mk's default rules
OVERRIDE_TARGETS := 1
include ../lib.mk

CURDIR := $(abspath .)
REPOROOT := $(abspath ../../../..)
TOOLSDIR := $(REPOROOT)/tools
LIBDIR := $(TOOLSDIR)/lib
TOOLSINCDIR := $(TOOLSDIR)/include
APIDIR := $(TOOLSINCDIR)/uapi
GENDIR := $(REPOROOT)/include/generated
GENHDR := $(GENDIR)/autoconf.h
SCXTOOLSINCDIR := $(TOOLSDIR)/sched_ext/include

# The schedulers are built by ../lib.bpf.mk: modern *.bpf.c layout, a
# .bpf.skel.h suffix, and subskeletons.
BPF_SRCS        := $(wildcard *.bpf.c)
BPF_SKEL_EXT    := .bpf.skel.h
BPF_GEN_SUBSKEL := 1
# Keep the generated files under build/ as before.  SCXOBJ_DIR (userspace
# objects) reuses the BPF object dir.
BPF_OBJ_DIR  := $(OUTPUT)/build/obj/sched_ext
BPF_SKEL_DIR := $(OUTPUT)/build/include
SCXOBJ_DIR   := $(BPF_OBJ_DIR)

include ../lib.bpf.mk

ifneq ($(wildcard $(GENHDR)),)
  GENFLAGS := -DHAVE_GENHDR
endif

CFLAGS += -g -O2 -rdynamic -pthread -Wall -Werror $(GENFLAGS)			\
	  -I$(GENDIR) -I$(LIBDIR) -I$(TOOLSINCDIR) -I$(APIDIR)			\
	  -I$(CURDIR)/include -I$(SCXTOOLSINCDIR)

# Silence some warnings when compiled with clang
ifneq ($(LLVM),)
CFLAGS += -Wno-unused-command-line-argument
endif

LDFLAGS = -lelf -lz -lpthread -lzstd

# The schedulers need scheduler-specific includes, so override BPF_CFLAGS
# wholesale and keep the flag set this directory used, rather than pin -Werror
# across clang versions.  The recipe adds -O2/--target/-mcpu.
BPF_CFLAGS = -g -D__TARGET_ARCH_$(SRCARCH) $(MENDIAN)				\
	     -I$(CURDIR)/include -I$(CURDIR)/include/bpf-compat			\
	     -I$(INCLUDE_DIR) -I$(APIDIR) -I$(SCXTOOLSINCDIR)			\
	     -I$(REPOROOT)/include						\
	     $(CLANG_SYS_INCLUDES)						\
	     -Wall -Wno-compare-distinct-pointer-types				\
	     -Wno-incompatible-function-pointer-types				\
	     -Wno-microsoft-anon-tag						\
	     -fms-extensions							\
	     $(BPF_EXTRA_CFLAGS)

EXTRA_CLEAN += $(OUTPUT)/build

################
# C schedulers #
################

# Every testcase takes all of the BPF progs as dependencies by default. This
# allows testcases to load any BPF scheduler, which is useful for testcases
# that don't need their own prog to run their test.
all_test_bpfprogs := $(BPF_SKELS)

auto-test-targets :=			\
	create_dsq			\
	dequeue				\
	enq_last_no_enq_fails		\
	ddsp_bogus_dsq_fail		\
	ddsp_vtimelocal_fail		\
	dsp_local_on			\
	enq_select_cpu			\
	exit				\
	hotplug				\
	init_enable_count		\
	maximal				\
	maybe_null			\
	minimal				\
	non_scx_kfunc_deny		\
	nohz_tick			\
	numa				\
	allowed_cpus			\
	peek_dsq			\
	prog_run			\
	reload_loop			\
	select_cpu_dfl			\
	select_cpu_dfl_nodispatch	\
	select_cpu_dispatch		\
	select_cpu_dispatch_bad_dsq	\
	select_cpu_dispatch_dbl_dsp	\
	select_cpu_vtime		\
	rt_stall			\
	test_example			\
	total_bw			\
	cyclic_kick_wait		\

testcase-targets := $(addsuffix .o,$(addprefix $(SCXOBJ_DIR)/,$(auto-test-targets)))

$(SCXOBJ_DIR)/runner.o: runner.c | $(SCXOBJ_DIR) $(BPFOBJ)
	$(call msg,CC,,$@)
	$(Q)$(CC) $(CFLAGS) -c $< -o $@

# Create all of the test targets object files, whose testcase objects will be
# registered into the runner in ELF constructors.
#
# Note that we must do double expansion here in order to support conditionally
# compiling BPF object files only if one is present, as the wildcard Make
# function doesn't support using implicit rules otherwise.
$(testcase-targets): $(SCXOBJ_DIR)/%.o: %.c $(SCXOBJ_DIR)/runner.o $(all_test_bpfprogs) | $(SCXOBJ_DIR)
	$(call msg,CC,,$@)
	$(Q)$(CC) $(CFLAGS) -c $< -o $@

$(SCXOBJ_DIR)/util.o: util.c | $(SCXOBJ_DIR)
	$(call msg,CC,,$@)
	$(Q)$(CC) $(CFLAGS) -c $< -o $@

$(OUTPUT)/runner: $(SCXOBJ_DIR)/runner.o $(SCXOBJ_DIR)/util.o $(BPFOBJ) $(testcase-targets)
	$(call msg,BINARY,,$@)
	$(Q)$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

.DEFAULT_GOAL := all

.DELETE_ON_ERROR:

.SECONDARY:
