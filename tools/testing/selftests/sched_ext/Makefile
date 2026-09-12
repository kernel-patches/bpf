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
GENDIR := $(REPOROOT)/include/generated
GENHDR := $(GENDIR)/autoconf.h
SCXTOOLSINCDIR := $(TOOLSDIR)/sched_ext/include

# Build scheduler skeletons and subskeletons with the shared BPF rules.
BPF_SRCS        := $(wildcard *.bpf.c)
BPF_SKEL_EXT    := .bpf.skel.h
BPF_GEN_SUBSKEL := 1
# Preserve the existing build/ layout.
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

# Preserve the scheduler-specific flags; the shared recipe adds target flags.
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

# Build every scheduler before each test.
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
