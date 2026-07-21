# SPDX-License-Identifier: GPL-2.0
#
# BPF selftests build.
#
# The build is split in two layers:
#
#   Makefile (this file)
#       Everything that exists once: knobs and toolchain setup, libbpf /
#       bpftool / resolve_btfids sub-builds, vmlinux.h, signing keys,
#       generated tests.h headers, shared helper objects, standalone test
#       binaries (bench, veristat, test_verifier, xsk*, ...), kernel test
#       modules, docs, and the kselftest lib.mk run/install/clean
#       contract.
#
#   Makefile.runner
#       One test-runner instance (test_progs, test_progs-<flavor>,
#       test_maps): BPF objects, skeleton headers, test objects and the
#       final runner binary. Invoked from here once per instance; each
#       invocation is an independent single-flavor namespace, so the
#       runner is plain make without $$-escaping or eval.
#
#   gen_bpf_skel.sh
#       Links BPF objects via bpftool and generates (light) skeletons;
#       one script instead of four near-identical make recipes.
#
# Shared definitions (paths, flags, permissive-mode helpers) live in
# Makefile.buildvars, included by both layers.

include ../../../build/Build.include
include ../../../scripts/Makefile.arch
include ../../../scripts/Makefile.include

# These probes gate the flavor list, which must be final before lib.mk is
# included; keep values consistent with Makefile.buildvars.
ifeq ($(origin BPF_GCC),undefined)
BPF_GCC := $(shell command -v bpf-gcc;)
endif
ifneq ($(shell $(CLANG) --target=bpf -mcpu=help 2>&1 | grep 'v4'),)
CLANG_CPUV4 := 1
endif

# Order correspond to 'make run_tests' order
TEST_GEN_PROGS = test_verifier test_tag test_maps test_lru_map test_progs \
	test_sockmap \
	test_tcpnotify_user \
	test_progs-no_alu32
TEST_INST_SUBDIRS := no_alu32

# Also test bpf-gcc, if present
ifneq ($(BPF_GCC),)
TEST_GEN_PROGS += test_progs-bpf_gcc
TEST_INST_SUBDIRS += bpf_gcc
endif

ifneq ($(CLANG_CPUV4),)
TEST_GEN_PROGS += test_progs-cpuv4
TEST_INST_SUBDIRS += cpuv4
endif

TEST_FILES = xsk_prereqs.sh $(wildcard progs/btf_dump_test_case_*.c)

# Order correspond to 'make run_tests' order
TEST_PROGS := test_kmod.sh \
	test_lirc_mode2.sh \
	test_bpftool_build.sh \
	test_doc_build.sh \
	test_xsk.sh \
	test_xdp_features.sh

TEST_PROGS_EXTENDED := \
	ima_setup.sh verify_sig_setup.sh

# Compile but not part of 'make run_tests'
TEST_GEN_PROGS_EXTENDED = \
	bench \
	flow_dissector_load \
	test_cpp \
	test_lirc_mode2_user \
	veristat \
	xdp_features \
	xdp_hw_metadata \
	xdp_synproxy \
	xskxceiver

TEST_KMODS ?= bpf_testmod.ko bpf_test_no_cfi.ko bpf_test_modorder_x.ko \
	bpf_test_modorder_y.ko bpf_test_rqspinlock.ko

TEST_GEN_FILES += $(TEST_KMODS) liburandom_read.so urandom_read sign-file uprobe_multi

# override lib.mk's default rules
OVERRIDE_TARGETS := 1
override define CLEAN
	$(call msg,CLEAN)
	$(Q)$(RM) -r $(TEST_GEN_PROGS)
	$(Q)$(RM) -r $(TEST_GEN_PROGS_EXTENDED)
	$(Q)$(RM) -r $(TEST_GEN_FILES)
	$(Q)$(RM) -r $(TEST_KMODS)
	$(Q)$(RM) -r $(EXTRA_CLEAN)
	$(Q)$(MAKE) -C test_kmods clean
	$(Q)$(MAKE) -C libarena clean
	$(Q)$(MAKE) docs-clean
endef

include ../lib.mk

NON_CHECK_FEAT_TARGETS := clean docs-clean emit_tests
CHECK_FEAT := $(filter-out $(NON_CHECK_FEAT_TARGETS),$(or $(MAKECMDGOALS),all))
ifneq ($(CHECK_FEAT),)
FEATURE_USER := .selftests
FEATURE_TESTS := llvm
FEATURE_DISPLAY := $(FEATURE_TESTS)

# Makefile.feature expects OUTPUT to end with a slash
ifeq ($(shell expr $(MAKE_VERSION) \>= 4.4), 1)
$(let OUTPUT,$(OUTPUT)/,\
	$(eval include ../../../build/Makefile.feature))
else
override OUTPUT := $(OUTPUT)/
$(eval include ../../../build/Makefile.feature)
override OUTPUT := $(patsubst %/,%,$(OUTPUT))
endif
endif

include Makefile.buildvars

ifneq ($(SKIP_LLVM),1)
ifeq ($(feature-llvm),1)
  LLVM_CFLAGS  += -DHAVE_LLVM_SUPPORT
  LLVM_CONFIG_LIB_COMPONENTS := mcdisassembler all-targets
  # both llvm-config and lib.mk add -D_GNU_SOURCE, which ends up as conflict
  LLVM_CFLAGS  += $(filter-out -D_GNU_SOURCE,$(shell $(LLVM_CONFIG) --cflags))
  # Cross compilation must use dynamic linking to avoid unresolved library
  # dependencies. For native build, prefer linking statically if it's
  # available, otherwise fallback to shared.
  ifneq ($(ARCH), $(HOSTARCH))
    LLVM_LINK_STATIC :=
  else
    LLVM_LINK_STATIC := $(shell $(LLVM_CONFIG) --link-static --libs >/dev/null 2>&1 && echo y)
  endif
  ifeq ($(LLVM_LINK_STATIC),y)
    LLVM_LDLIBS  += $(shell $(LLVM_CONFIG) --link-static --libs $(LLVM_CONFIG_LIB_COMPONENTS))
    LLVM_LDLIBS  += $(filter-out -lxml2,$(shell $(LLVM_CONFIG) --link-static --system-libs $(LLVM_CONFIG_LIB_COMPONENTS)))
    LLVM_LDLIBS  += -lstdc++
  else
    LLVM_LDLIBS  += $(shell $(LLVM_CONFIG) --link-shared --libs $(LLVM_CONFIG_LIB_COMPONENTS))
  endif
  LLVM_LDFLAGS += $(shell $(LLVM_CONFIG) --ldflags)
endif
endif

# Define simple and short `make test_progs`, `make test_maps`, etc targets
# to build individual tests.
# NOTE: Semicolon at the end is critical to override lib.mk's default static
# rule for binaries.
$(notdir $(TEST_GEN_PROGS) $(TEST_KMOD_TARGETS)				\
	 $(TEST_GEN_PROGS_EXTENDED)): %: $(OUTPUT)/% ;

# sort removes libbpf duplicates when not cross-building
MAKE_DIRS := $(sort $(BUILD_DIR)/libbpf $(HOST_BUILD_DIR)/libbpf	\
	       $(BUILD_DIR)/bpftool $(HOST_BUILD_DIR)/bpftool		\
	       $(HOST_BUILD_DIR)/resolve_btfids				\
	       $(INCLUDE_DIR))
$(MAKE_DIRS):
	$(call msg,MKDIR,,$@)
	$(Q)mkdir -p $@

$(OUTPUT)/%.o: %.c
	$(call msg,CC,,$@)
	$(Q)$(CC) $(CFLAGS) -c $(filter %.c,$^) -o $@

# Headers may appear among the prerequisites for dependency tracking;
# they must not reach the clang/gcc command line (clang treats a bare .h
# argument as a precompiled-header job and refuses -o).
$(OUTPUT)/%:%.c
	$(call msg,BINARY,,$@)
	$(Q)$(LINK.c) $(filter-out %.h,$^) $(LDLIBS) -o $@

# LLVM's ld.lld doesn't support all the architectures, so use it only on x86
ifeq ($(SRCARCH),$(filter $(SRCARCH),x86 riscv))
LLD := lld
else
LLD := $(shell command -v $(LD))
endif

# Filter out -static for liburandom_read.so and its dependent targets so that static builds
# do not fail. Static builds leave urandom_read relying on system-wide shared libraries.
$(OUTPUT)/liburandom_read.so: urandom_read_lib1.c urandom_read_lib2.c liburandom_read.map
	$(call msg,LIB,,$@)
	$(Q)$(CLANG) $(CLANG_TARGET_ARCH) \
		     $(filter-out -static,$(COMMON_CFLAGS) $(LDFLAGS)) \
		     $(filter %.c,$^) $(filter-out -static,$(LDLIBS)) \
		     -Wno-unused-command-line-argument \
		     -fuse-ld=$(LLD) -Wl,-znoseparate-code -Wl,--build-id=sha1 \
		     -Wl,--version-script=liburandom_read.map \
		     -fPIC -shared -o $@

$(OUTPUT)/urandom_read: urandom_read.c urandom_read_aux.c $(OUTPUT)/liburandom_read.so
	$(call msg,BINARY,,$@)
	$(Q)$(CLANG) $(CLANG_TARGET_ARCH) \
		     $(filter-out -static,$(COMMON_CFLAGS) $(LDFLAGS)) $(filter %.c,$^) \
		     -Wno-unused-command-line-argument \
		     -lurandom_read $(filter-out -static,$(LDLIBS)) -L$(OUTPUT) \
		     -fuse-ld=$(LLD) -Wl,-znoseparate-code -Wl,--build-id=sha1 \
		     -Wl,-rpath=. -o $@

$(OUTPUT)/sign-file: ../../../../scripts/sign-file.c
	$(call msg,SIGN-FILE,,$@)
	$(Q)$(CC) $(shell $(PKG_CONFIG) --cflags libcrypto 2> /dev/null) \
		  -I$(srctree)/tools/include/uapi/ \
		  $< -o $@ \
		  $(shell $(PKG_CONFIG) --libs libcrypto 2> /dev/null || echo -lcrypto)

# Linking uprobe_multi can fail due to relocation overflows on mips.
$(OUTPUT)/uprobe_multi: CFLAGS += $(if $(filter mips, $(ARCH)),-mxgot)
$(OUTPUT)/uprobe_multi: uprobe_multi.c uprobe_multi.ld
	$(call msg,BINARY,,$@)
	$(Q)$(CC) $(CFLAGS) -Wl,-T,uprobe_multi.ld -O0 $(LDFLAGS) 	\
		$(filter-out %.ld,$^) $(LDLIBS) -o $@

# This should really be a grouped target, but make versions before 4.3 don't
# support that for regular rules. However, pattern matching rules are implicitly
# treated as grouped even with older versions of make, so as a workaround, the
# subst() turns the rule into a pattern matching rule
$(addprefix test_kmods/,$(subst .ko,%ko,$(TEST_KMODS))): $(VMLINUX_BTF) $(RESOLVE_BTFIDS) $(wildcard test_kmods/Makefile test_kmods/*.[ch])
	$(Q)$(RM) test_kmods/*.ko test_kmods/*.mod.o # force re-compilation
	$(Q)$(MAKE) $(submake_extras) -C test_kmods				\
		$(if $(O),O=$(abspath $(O)))					\
		$(if $(KBUILD_OUTPUT),KBUILD_OUTPUT=$(abspath $(KBUILD_OUTPUT)))\
		RESOLVE_BTFIDS=$(RESOLVE_BTFIDS)				\
		EXTRA_CFLAGS='' EXTRA_LDFLAGS=''

$(TEST_KMOD_TARGETS): $(addprefix test_kmods/,$(TEST_KMODS))
	$(call msg,MOD,,$@)
	$(Q)$(if $(PERMISSIVE),if [ -f test_kmods/$(@F) ]; then )cp test_kmods/$(@F) $@$(if $(PERMISSIVE),; fi)


$(TEST_GEN_PROGS) $(TEST_GEN_PROGS_EXTENDED): $(BPFOBJ)

# ---------------------------------------------------------------------
# Tool sub-builds: bpftool and libbpf (host and, when cross-compiling,
# target variants) and resolve_btfids.
#
# Note the deliberate asymmetry: the host libbpf builds without
# sanitizers and with the host toolchain.
# ---------------------------------------------------------------------

$(DEFAULT_BPFTOOL): $(wildcard $(BPFTOOLDIR)/*.[ch] $(BPFTOOLDIR)/Makefile)    \
		    $(HOST_BPFOBJ) | $(HOST_BUILD_DIR)/bpftool
	$(Q)$(MAKE) $(submake_extras)  -C $(BPFTOOLDIR)			       \
		    ARCH= CROSS_COMPILE= CC="$(HOSTCC)" LD="$(HOSTLD)" 	       \
		    EXTRA_CFLAGS='-g $(OPT_FLAGS) $(SAN_CFLAGS) $(EXTRA_CFLAGS)'	       \
		    EXTRA_LDFLAGS='$(SAN_LDFLAGS) $(EXTRA_LDFLAGS)'			       \
		    OUTPUT=$(HOST_BUILD_DIR)/bpftool/			       \
		    LIBBPF_OUTPUT=$(HOST_BUILD_DIR)/libbpf/		       \
		    LIBBPF_DESTDIR=$(HOST_SCRATCH_DIR)/			       \
		    SKIP_LLVM=$(SKIP_LLVM)				       \
		    SKIP_LIBBFD=$(SKIP_LIBBFD)				       \
		    SKIP_CRYPTO=$(SKIP_CRYPTO)				       \
		    prefix= DESTDIR=$(HOST_SCRATCH_DIR)/ install-bin

ifneq ($(CROSS_COMPILE),)
$(CROSS_BPFTOOL): $(wildcard $(BPFTOOLDIR)/*.[ch] $(BPFTOOLDIR)/Makefile)	\
		    $(BPFOBJ) | $(BUILD_DIR)/bpftool
	$(Q)$(MAKE) $(submake_extras)  -C $(BPFTOOLDIR)				\
		    ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE)			\
		    EXTRA_CFLAGS='-g $(OPT_FLAGS) $(SAN_CFLAGS) $(EXTRA_CFLAGS)'	       \
		    EXTRA_LDFLAGS='$(SAN_LDFLAGS) $(EXTRA_LDFLAGS)'			       \
		    OUTPUT=$(BUILD_DIR)/bpftool/				\
		    LIBBPF_OUTPUT=$(BUILD_DIR)/libbpf/				\
		    LIBBPF_DESTDIR=$(SCRATCH_DIR)/				\
		    SKIP_LLVM=$(SKIP_LLVM)					\
		    SKIP_LIBBFD=$(SKIP_LIBBFD)					\
		    SKIP_CRYPTO=$(SKIP_CRYPTO)					\
		    prefix= DESTDIR=$(SCRATCH_DIR)/ install-bin
endif

$(BPFOBJ): $(wildcard $(BPFDIR)/*.[ch] $(BPFDIR)/Makefile)		       \
	   $(APIDIR)/linux/bpf.h					       \
	   | $(BUILD_DIR)/libbpf
	$(Q)$(MAKE) $(submake_extras) -C $(BPFDIR) OUTPUT=$(BUILD_DIR)/libbpf/ \
		    EXTRA_CFLAGS='-g $(OPT_FLAGS) $(SAN_CFLAGS) $(EXTRA_CFLAGS)' \
		    EXTRA_LDFLAGS='$(SAN_LDFLAGS) $(EXTRA_LDFLAGS)'	       \
		    DESTDIR=$(SCRATCH_DIR) prefix= all install_headers

ifneq ($(BPFOBJ),$(HOST_BPFOBJ))
$(HOST_BPFOBJ): $(wildcard $(BPFDIR)/*.[ch] $(BPFDIR)/Makefile)		       \
		$(APIDIR)/linux/bpf.h					       \
		| $(HOST_BUILD_DIR)/libbpf
	$(Q)$(MAKE) $(submake_extras) -C $(BPFDIR)                             \
		    ARCH= CROSS_COMPILE=				       \
		    EXTRA_CFLAGS='-g $(OPT_FLAGS) $(EXTRA_CFLAGS)'	       \
		    EXTRA_LDFLAGS='$(EXTRA_LDFLAGS)'			       \
		    OUTPUT=$(HOST_BUILD_DIR)/libbpf/			       \
		    CC="$(HOSTCC)" LD="$(HOSTLD)"			       \
		    DESTDIR=$(HOST_SCRATCH_DIR)/ prefix= all install_headers
endif

$(RESOLVE_BTFIDS): $(HOST_BPFOBJ) | $(HOST_BUILD_DIR)/resolve_btfids	\
		       $(TOOLSDIR)/bpf/resolve_btfids/main.c	\
		       $(TOOLSDIR)/lib/rbtree.c			\
		       $(TOOLSDIR)/lib/zalloc.c			\
		       $(TOOLSDIR)/lib/string.c			\
		       $(TOOLSDIR)/lib/ctype.c			\
		       $(TOOLSDIR)/lib/str_error_r.c
	$(Q)$(MAKE) $(submake_extras) -C $(TOOLSDIR)/bpf/resolve_btfids	\
		CC="$(HOSTCC)" LD="$(HOSTLD)" AR="$(HOSTAR)" \
		LIBBPF_INCLUDE=$(HOST_INCLUDE_DIR) \
		EXTRA_LDFLAGS='$(SAN_LDFLAGS) $(EXTRA_LDFLAGS)' \
		HOSTPKG_CONFIG='$(PKG_CONFIG)' \
		OUTPUT=$(HOST_BUILD_DIR)/resolve_btfids/ BPFOBJ=$(HOST_BPFOBJ)

ifneq ($(SKIP_DOCS),1)
all: docs
endif

docs:
	$(Q)RST2MAN_OPTS="--exit-status=1" $(MAKE) $(submake_extras)	\
	            -f Makefile.docs					\
	            prefix= OUTPUT=$(OUTPUT)/ DESTDIR=$(OUTPUT)/ $@

docs-clean:
	$(Q)$(MAKE) $(submake_extras)					\
	            -f Makefile.docs					\
	            prefix= OUTPUT=$(OUTPUT)/ DESTDIR=$(OUTPUT)/ $@

# vmlinux.h is first dumped to a temporary file and then compared to
# the previous version. This helps to avoid unnecessary re-builds of
# BPF objects.
$(INCLUDE_DIR)/vmlinux.h: $(VMLINUX_BTF) $(BPFTOOL) | $(INCLUDE_DIR)
ifeq ($(VMLINUX_H),)
	$(call msg,GEN,,$@)
	$(Q)$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $(INCLUDE_DIR)/.vmlinux.h.tmp
	$(Q)cmp -s $(INCLUDE_DIR)/.vmlinux.h.tmp $@ || mv $(INCLUDE_DIR)/.vmlinux.h.tmp $@
else
	$(call msg,CP,,$@)
	$(Q)cp "$(VMLINUX_H)" $@
endif

# One genkey run produces both files. A plain two-target rule is not
# grouped - under -j make would run genkey twice concurrently and the
# openssl invocations race; the pattern form is implicitly grouped even
# with make < 4.3 (same workaround as the test_kmods rule).
$(BUILD_DIR)/%.pem $(BUILD_DIR)/%.der: $(VERIFY_SIG_SETUP)
	$(Q)mkdir -p $(BUILD_DIR)
	$(Q)$(VERIFY_SIG_SETUP) genkey $(BUILD_DIR)

# Generates a header with C array declaration, containing test_progs_verification_cert bytes
$(VERIFY_SIG_HDR): $(VERIFICATION_CERT)
	$(Q)(echo "unsigned char test_progs_verification_cert[] = {"; \
	 od -v -t 'xC' -w12 $< | sed 's/ \(\S\+\)/ 0x\1,/g;s/^\S\+/ /;$$d'; \
	 echo "};"; \
	 echo "unsigned int test_progs_verification_cert_len = $$(wc -c < $<);") > $@

LIBARENA_MAKE_ARGS = \
		BPFTOOL="$(BPFTOOL)" \
		INCLUDE_DIR="$(INCLUDE_DIR)" \
		LIBBPF_INCLUDE="$(HOST_INCLUDE_DIR)" \
		BPFOBJ="$(BPFOBJ)" \
		LDLIBS="$(LDLIBS) -lzstd" \
		CLANG="$(CLANG)" \
		BPF_CFLAGS="$(BPF_CFLAGS) $(CLANG_CFLAGS)" \
		BPF_TARGET_ENDIAN="$(BPF_TARGET_ENDIAN)" \
		Q="$(Q)"

LIBARENA_BPF_DEPS := $(wildcard libarena/Makefile		\
				 libarena/include/*		\
				 libarena/include/libarena/*	\
				 libarena/src/*			\
				 libarena/selftests/*		\
				 libarena/*.bpf.o)

$(LIBARENA_SKEL): $(INCLUDE_DIR)/vmlinux.h $(BPFOBJ) $(LIBARENA_BPF_DEPS)
	+$(MAKE) -C libarena libarena.skel.h $(LIBARENA_MAKE_ARGS)

libarena: $(LIBARENA_SKEL)

ifneq ($(CLANG_HAS_ARENA_ASAN),)
$(LIBARENA_ASAN_SKEL): $(INCLUDE_DIR)/vmlinux.h $(BPFOBJ) $(LIBARENA_BPF_DEPS)
	+$(MAKE) -C libarena libarena_asan.skel.h $(LIBARENA_MAKE_ARGS)

libarena_asan: $(LIBARENA_ASAN_SKEL)
endif

# ---------------------------------------------------------------------
# Generated test list headers
# ---------------------------------------------------------------------

define gen_tests_hdr
	$(call msg,TEST-HDR,,$@)
	$(Q)(echo '/* Generated header, do not edit */';		\
	     sed -n -E 's/^void (serial_)?test_([a-zA-Z0-9_]+)\((void)?\).*/DEFINE_TEST(\2)/p' \
		$(@D)/*.c | sort) > $@
endef

prog_tests/tests.h: $(wildcard prog_tests/*.c)
	$(gen_tests_hdr)

map_tests/tests.h: $(wildcard map_tests/*.c)
	$(gen_tests_hdr)

verifier/tests.h: verifier/*.c
	$(Q)( cd verifier/; \
	      echo '/* Generated header, do not edit */'; \
	      echo '#ifdef FILL_ARRAY'; \
	      ls *.c 2> /dev/null | sed -e 's@\(.*\)@#include \"\1\"@'; \
	      echo '#endif' \
	    ) > verifier/tests.h

# ---------------------------------------------------------------------
# Shared helper objects, used by the standalone binaries below and (as
# prebuilt inputs) by the unflavored test_progs runner.
# ---------------------------------------------------------------------

# Some utility functions use LLVM libraries
$(OUTPUT)/jit_disasm_helpers.o: CFLAGS += $(LLVM_CFLAGS)

HELPER_OBJS := $(addprefix $(OUTPUT)/,testing_helpers.o cgroup_helpers.o \
	       trace_helpers.o network_helpers.o json_writer.o		\
	       cap_helpers.o unpriv_helpers.o usdt_1.o usdt_2.o xsk.o)

# $(BPFTOOL) is a prerequisite because its sub-make is what installs
# libbpf's internal headers (bpf/hashmap.h, bpf/libbpf_internal.h) into
# $(INCLUDE_DIR); without it, helpers including those headers race the
# install and can silently pick up the source-tree copies instead.
#
# Invariant: this list must be a superset of every prerequisite the
# runner's EXTRA_OBJS rule attaches to these same objects (EXTRA_HDRS,
# both tests.h flavors, $(BPFOBJ)). It guarantees the helpers built
# here are never older than a runner-side prerequisite, so the
# unflavored test_progs and test_maps sub-makes, which share $(OUTPUT),
# treat them as up to date instead of both recompiling the same object
# file concurrently.
$(HELPER_OBJS): flow_dissector_load.h ip_check_defrag_frags.h		\
		$(VERIFY_SIG_HDR) $(LIBARENA_SKEL) $(LIBARENA_ASAN_SKEL)\
		prog_tests/tests.h map_tests/tests.h $(BPFOBJ) $(BPFTOOL)

$(OUTPUT)/test_sockmap: $(OUTPUT)/cgroup_helpers.o $(OUTPUT)/testing_helpers.o
$(OUTPUT)/test_tcpnotify_user: $(OUTPUT)/cgroup_helpers.o		\
			       $(OUTPUT)/testing_helpers.o		\
			       $(OUTPUT)/trace_helpers.o
$(OUTPUT)/test_tag: $(OUTPUT)/testing_helpers.o
$(OUTPUT)/test_lirc_mode2_user: $(OUTPUT)/testing_helpers.o
$(OUTPUT)/flow_dissector_load: flow_dissector_load.h $(OUTPUT)/testing_helpers.o

# ---------------------------------------------------------------------
# Test runner instances, one sub-make each (see Makefile.runner).
# ---------------------------------------------------------------------

# The LLVM feature-probe results are exported to the runner sub-makes.
# CC is passed explicitly instead: exporting it would also leak lib.mk's
# CC into the libbpf/bpftool/resolve_btfids sub-builds, which compute
# their own.
export LLVM_CFLAGS LLVM_LDLIBS LLVM_LDFLAGS

RUNNER_MAKE := $(MAKE) -f Makefile.runner OUTPUT=$(OUTPUT) CC='$(CC)'

# Everything a runner instance references but does not know how to build.
RUNNER_PREREQS := $(INCLUDE_DIR)/vmlinux.h $(BPFOBJ) $(BPFTOOL)		\
		  $(TRUNNER_BPFTOOL) $(RESOLVE_BTFIDS)			\
		  $(OUTPUT)/veristat					\
		  $(VERIFY_SIG_HDR) $(PRIVATE_KEY) $(VERIFICATION_CERT)	\
		  $(LIBARENA_SKEL) $(LIBARENA_ASAN_SKEL)		\
		  prog_tests/tests.h					\
		  $(HELPER_OBJS)					\
		  $(OUTPUT)/urandom_read $(OUTPUT)/liburandom_read.so	\
		  $(OUTPUT)/xdp_synproxy $(OUTPUT)/sign-file		\
		  $(OUTPUT)/uprobe_multi $(TEST_KMOD_TARGETS)

FORCE:

# The default flavor's skeletons are also inputs of bench, test_maps,
# xskxceiver, xdp_* and test_cpp; "default-skels" builds just those
# without the test_progs test objects and binary.
.PHONY: default-skels
default-skels: $(RUNNER_PREREQS)
	+$(Q)$(RUNNER_MAKE) RUNNER=test_progs FLAVOR= TESTS_DIR=prog_tests \
		BPF_BUILD=clang BPF_MCPU=v3 BPF_DEFINES=-DENABLE_ATOMICS_TESTS skels

$(OUTPUT)/test_progs: $(RUNNER_PREREQS) default-skels FORCE
	+$(Q)$(RUNNER_MAKE) RUNNER=test_progs FLAVOR= TESTS_DIR=prog_tests \
		BPF_BUILD=clang BPF_MCPU=v3 BPF_DEFINES=-DENABLE_ATOMICS_TESTS

$(OUTPUT)/test_progs-no_alu32: $(RUNNER_PREREQS) FORCE
	+$(Q)$(RUNNER_MAKE) RUNNER=test_progs FLAVOR=no_alu32 TESTS_DIR=prog_tests \
		BPF_BUILD=clang BPF_MCPU=v2

ifneq ($(CLANG_CPUV4),)
$(OUTPUT)/test_progs-cpuv4: $(RUNNER_PREREQS) FORCE
	+$(Q)$(RUNNER_MAKE) RUNNER=test_progs FLAVOR=cpuv4 TESTS_DIR=prog_tests \
		BPF_BUILD=clang BPF_MCPU=v4 BPF_DEFINES=-DENABLE_ATOMICS_TESTS
endif

ifneq ($(BPF_GCC),)
$(OUTPUT)/test_progs-bpf_gcc: $(RUNNER_PREREQS) FORCE
	+$(Q)$(RUNNER_MAKE) RUNNER=test_progs FLAVOR=bpf_gcc TESTS_DIR=prog_tests \
		BPF_BUILD=gcc
endif

# test_maps compiles map_tests/*.c against the default flavor's skeletons
$(OUTPUT)/test_maps: $(RUNNER_PREREQS) map_tests/tests.h default-skels FORCE
	+$(Q)$(RUNNER_MAKE) RUNNER=test_maps FLAVOR= TESTS_DIR=map_tests \
		BPF_BUILD=none

# Default-flavor BPF objects and skeletons consumed by targets in this
# Makefile (and by lib.mk's install rule) are produced by the runner
# sub-make above; the empty recipe plus the order-only prerequisite
# makes them available here without duplicating the runner's rules.
DEFAULT_BPF_OBJS := $(patsubst progs/%.c,$(OUTPUT)/%.bpf.o,$(wildcard progs/*.c))
TEST_GEN_FILES += $(DEFAULT_BPF_OBJS)

BENCH_SKELS := $(addprefix $(OUTPUT)/,					\
	       test_overhead.skel.h trigger_bench.skel.h		\
	       ringbuf_bench.skel.h perfbuf_bench.skel.h		\
	       bloom_filter_bench.skel.h bpf_loop_bench.skel.h		\
	       strncmp_bench.skel.h bpf_hashmap_full_update_bench.skel.h\
	       local_storage_bench.skel.h				\
	       local_storage_rcu_tasks_trace_bench.skel.h		\
	       bench_local_storage_create.skel.h			\
	       bpf_hashmap_lookup.skel.h htab_mem_bench.skel.h		\
	       crypto_bench.skel.h bench_sockmap_prog.skel.h		\
	       lpm_trie_bench.skel.h lpm_trie_map.skel.h		\
	       bpf_nop_bench.skel.h xdp_lb_bench.skel.h)
TOP_SKELS := $(addprefix $(OUTPUT)/,xsk_xdp_progs.skel.h		\
	     xdp_hw_metadata.skel.h xdp_features.skel.h			\
	     test_core_extern.skel.h) $(BENCH_SKELS)

# Empty-recipe delegation: "default-skels" (re)builds the file via the
# runner sub-make, after which make re-stats the target, so dependents
# see fresh timestamps within the same invocation. Dependents still
# rebuild on mtime only - the phony prerequisite does not cascade.
$(DEFAULT_BPF_OBJS) $(TOP_SKELS): default-skels ;

# ---------------------------------------------------------------------
# Standalone test binaries
# ---------------------------------------------------------------------

# test_verifier is much simpler than test_maps/test_progs and
# sufficiently different from them (e.g., its tests.h uses a completely
# different pattern), that it's worth just defining its rules explicitly.
$(OUTPUT)/test_verifier: test_verifier.c verifier/tests.h $(BPFOBJ)	\
			 $(OUTPUT)/testing_helpers.o			\
			 $(OUTPUT)/cap_helpers.o			\
			 $(OUTPUT)/unpriv_helpers.o
	$(call msg,BINARY,,$@)
	$(Q)$(CC) $(CFLAGS) $(filter %.a %.o %.c,$^) $(LDLIBS) -o $@

# Include find_bit.c to compile xskxceiver.
EXTRA_SRC := $(TOOLSDIR)/lib/find_bit.c prog_tests/test_xsk.c prog_tests/test_xsk.h
$(OUTPUT)/xskxceiver: $(EXTRA_SRC) xskxceiver.c xskxceiver.h $(OUTPUT)/network_helpers.o $(OUTPUT)/xsk.o $(OUTPUT)/xsk_xdp_progs.skel.h $(BPFOBJ)
	$(call msg,BINARY,,$@)
	$(Q)$(CC) $(CFLAGS) $(filter %.a %.o %.c,$^) $(LDLIBS) -o $@

$(OUTPUT)/xdp_hw_metadata: xdp_hw_metadata.c $(OUTPUT)/network_helpers.o $(OUTPUT)/xsk.o $(OUTPUT)/xdp_hw_metadata.skel.h
	$(call msg,BINARY,,$@)
	$(Q)$(CC) $(CFLAGS) $(filter %.a %.o %.c,$^) $(LDLIBS) -o $@

$(OUTPUT)/xdp_features: xdp_features.c $(OUTPUT)/network_helpers.o $(OUTPUT)/xdp_features.skel.h
	$(call msg,BINARY,,$@)
	$(Q)$(CC) $(CFLAGS) $(filter %.a %.o %.c,$^) $(LDLIBS) -o $@

# Make sure we are able to include and link libbpf against c++.
CXXFLAGS += $(CFLAGS)
CXXFLAGS := $(subst -D_GNU_SOURCE=,,$(CXXFLAGS))
CXXFLAGS := $(subst -std=gnu11,-std=gnu++11,$(CXXFLAGS))
$(OUTPUT)/test_cpp: test_cpp.cpp $(OUTPUT)/test_core_extern.skel.h $(BPFOBJ)
	$(call msg,CXX,,$@)
	$(Q)$(CXX) $(CXXFLAGS) $(filter %.a %.o %.cpp,$^) $(LDLIBS) -o $@

# ---------------------------------------------------------------------
# Benchmark runner. The benchmark list is defined by the files in
# benchs/: every benchs/bench_*.c is compiled and linked in.
# ---------------------------------------------------------------------

BENCH_OBJS := $(sort $(patsubst benchs/%.c,$(OUTPUT)/%.o,$(wildcard benchs/bench_*.c)))

$(OUTPUT)/bench_%.o: benchs/bench_%.c bench.h $(BPFOBJ) | default-skels
	$(call msg,CC,,$@)
	$(Q)$(CC) $(CFLAGS) -O2 -c $(filter %.c,$^) -o $@ $(call skip_on_fail,BENCH)

# benchmark-specific generated-skeleton dependencies
$(OUTPUT)/bench_rename.o: $(OUTPUT)/test_overhead.skel.h
$(OUTPUT)/bench_trigger.o: $(OUTPUT)/trigger_bench.skel.h
$(OUTPUT)/bench_ringbufs.o: $(OUTPUT)/ringbuf_bench.skel.h \
			    $(OUTPUT)/perfbuf_bench.skel.h
$(OUTPUT)/bench_bloom_filter_map.o: $(OUTPUT)/bloom_filter_bench.skel.h
$(OUTPUT)/bench_bpf_loop.o: $(OUTPUT)/bpf_loop_bench.skel.h
$(OUTPUT)/bench_strncmp.o: $(OUTPUT)/strncmp_bench.skel.h
$(OUTPUT)/bench_bpf_hashmap_full_update.o: $(OUTPUT)/bpf_hashmap_full_update_bench.skel.h
$(OUTPUT)/bench_local_storage.o: $(OUTPUT)/local_storage_bench.skel.h
$(OUTPUT)/bench_local_storage_rcu_tasks_trace.o: $(OUTPUT)/local_storage_rcu_tasks_trace_bench.skel.h
$(OUTPUT)/bench_local_storage_create.o: $(OUTPUT)/bench_local_storage_create.skel.h
$(OUTPUT)/bench_bpf_hashmap_lookup.o: $(OUTPUT)/bpf_hashmap_lookup.skel.h
$(OUTPUT)/bench_htab_mem.o: $(OUTPUT)/htab_mem_bench.skel.h
$(OUTPUT)/bench_bpf_crypto.o: $(OUTPUT)/crypto_bench.skel.h
$(OUTPUT)/bench_sockmap.o: $(OUTPUT)/bench_sockmap_prog.skel.h
$(OUTPUT)/bench_lpm_trie_map.o: $(OUTPUT)/lpm_trie_bench.skel.h $(OUTPUT)/lpm_trie_map.skel.h
$(OUTPUT)/bench_bpf_nop.o: $(OUTPUT)/bpf_nop_bench.skel.h bench_bpf_timing.h
$(OUTPUT)/bench_xdp_lb.o: $(OUTPUT)/xdp_lb_bench.skel.h bench_bpf_timing.h
$(OUTPUT)/bench_bpf_timing.o: bench_bpf_timing.h

$(OUTPUT)/bench.o: bench.h testing_helpers.h $(BPFOBJ)
$(OUTPUT)/bench: LDLIBS += -lm
$(OUTPUT)/bench: $(OUTPUT)/bench.o		\
		 $(OUTPUT)/testing_helpers.o	\
		 $(OUTPUT)/trace_helpers.o	\
		 $(OUTPUT)/cgroup_helpers.o	\
		 $(OUTPUT)/usdt_1.o		\
		 $(OUTPUT)/usdt_2.o		\
		 $(BENCH_OBJS)
	$(call msg,BINARY,,$@)
	$(Q)$(CC) $(CFLAGS) $(LDFLAGS) $(filter %.a %.o,$^) $(LDLIBS) -o $@ \
		$(call skip_on_fail,LINK,,(some benchmarks may have been skipped))

# This works around GCC warning about snprintf truncating strings like:
#
#   char a[PATH_MAX], b[PATH_MAX];
#   snprintf(a, "%s/foo", b);      // triggers -Wformat-truncation
$(OUTPUT)/veristat.o: CFLAGS += -Wno-format-truncation
$(OUTPUT)/veristat.o: $(BPFOBJ)
$(OUTPUT)/veristat: $(OUTPUT)/veristat.o
	$(call msg,BINARY,,$@)
	$(Q)$(CC) $(CFLAGS) $(LDFLAGS) $(filter %.a %.o,$^) $(LDLIBS) -o $@

EXTRA_CLEAN := $(SCRATCH_DIR) $(HOST_SCRATCH_DIR)			\
	prog_tests/tests.h map_tests/tests.h verifier/tests.h		\
	feature bpftool $(TEST_KMOD_TARGETS)				\
	$(addprefix $(OUTPUT)/,*.o *.d *.skel.h *.lskel.h *.subskel.h	\
			       *.BTF *.BTF_ids *.BTF.base		\
			       no_alu32 cpuv4 bpf_gcc			\
			       liburandom_read.so)			\
	$(OUTPUT)/FEATURE-DUMP.selftests

.PHONY: docs docs-clean libarena libarena_asan

# Delete partially updated (corrupted) files on error
.DELETE_ON_ERROR:

# When permissive, tell rsync to ignore missing source arguments so that
# partial builds do not abort installation.
ifneq ($(PERMISSIVE),)
override define INSTALL_SINGLE_RULE
	$(if $(INSTALL_LIST),@mkdir -p $(INSTALL_PATH))
	$(if $(INSTALL_LIST),rsync -a --copy-unsafe-links --ignore-missing-args $(INSTALL_LIST) $(INSTALL_PATH)/)
endef
endif

DEFAULT_INSTALL_RULE := $(INSTALL_RULE)
override define INSTALL_RULE
	$(DEFAULT_INSTALL_RULE)
	@mkdir -p $(INSTALL_PATH)/tools/sbin
	@rsync -a $(if $(PERMISSIVE),--ignore-missing-args) $(TRUNNER_BPFTOOL) $(INSTALL_PATH)/tools/sbin/
	@rsync -a $(if $(PERMISSIVE),--ignore-missing-args) $(OUTPUT)/*.BTF $(INSTALL_PATH)/
	@for DIR in $(TEST_INST_SUBDIRS); do				  \
		mkdir -p $(INSTALL_PATH)/$$DIR;				  \
		rsync -a $(if $(PERMISSIVE),--ignore-missing-args)	  \
			$(OUTPUT)/$$DIR/*.bpf.o $(OUTPUT)/$$DIR/*.BTF \
			$(INSTALL_PATH)/$$DIR;				  \
	done
endef
