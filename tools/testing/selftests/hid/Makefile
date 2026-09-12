# SPDX-License-Identifier: GPL-2.0

# based on tools/testing/selftest/bpf/Makefile
include ../../../build/Build.include
include ../../../scripts/Makefile.arch
include ../../../scripts/Makefile.include

TEST_PROGS := hid-core.sh
TEST_PROGS += hid-apple.sh
TEST_PROGS += hid-gamepad.sh
TEST_PROGS += hid-ite.sh
TEST_PROGS += hid-keyboard.sh
TEST_PROGS += hid-mouse.sh
TEST_PROGS += hid-multitouch.sh
TEST_PROGS += hid-sony.sh
TEST_PROGS += hid-tablet.sh
TEST_PROGS += hid-usb_crash.sh
TEST_PROGS += hid-wacom.sh

TEST_FILES := run-hid-tools-tests.sh
TEST_FILES += tests

CXX ?= $(CROSS_COMPILE)g++

HOSTPKG_CONFIG := pkg-config

CFLAGS += -g -O0 -rdynamic -Wall -Werror -I$(OUTPUT) $(KHDR_INCLUDES)
CFLAGS += -I$(OUTPUT)/tools/include

LDLIBS += -lelf -lz -lrt -lpthread

# Silence some warnings when compiled with clang
ifneq ($(LLVM),)
CFLAGS += -Wno-unused-command-line-argument
endif

# Order correspond to 'make run_tests' order
TEST_GEN_PROGS = hid_bpf hidraw

# Emit succinct information message describing current building step
# $1 - generic step name (e.g., CC, LINK, etc);
# $2 - optional "flavor" specifier; if provided, will be emitted as [flavor];
# $3 - target (assumed to be file); only file name will be emitted;
# $4 - optional extra arg, emitted as-is, if provided.
ifeq ($(V),1)
msg =
else
msg = @printf '  %-8s%s %s%s\n' "$(1)" "$(if $(2), [$(2)])" "$(notdir $(3))" "$(if $(4), $(4))";
MAKEFLAGS += --no-print-directory
endif

# override lib.mk's default rules
OVERRIDE_TARGETS := 1
override define CLEAN
	$(call msg,CLEAN)
	$(Q)$(RM) -r $(TEST_GEN_PROGS)
	$(Q)$(RM) -r $(EXTRA_CLEAN)
endef

# Build the legacy progs/*.c layout with the shared BPF rules.
BPF_SRCS       := $(wildcard progs/*.c)
BPF_PROG_EXT   := .c
# BPFDIR is defined when this recursive variable is expanded.
BPF_EXTRA_HDRS  = $(wildcard progs/*.h) $(wildcard $(BPFDIR)/hid_bpf_*.h) \
		  $(wildcard $(BPFDIR)/*.bpf.h)

include ../lib.mk
include ../lib.bpf.mk

# Preserve the existing install list.
TEST_GEN_FILES += $(BPF_OBJS)
TEST_GEN_PROGS_EXTENDED += $(DEFAULT_BPFTOOL)

# Keep aliases such as "make hid_bpf" from matching lib.mk's binary rule.
$(notdir $(TEST_GEN_PROGS)): %: $(OUTPUT)/% ;

# Relink tests when the in-tree libbpf changes.
$(TEST_GEN_PROGS): $(BPFOBJ)

$(OUTPUT)/%.o: %.c $(BPF_SKELS) hid_common.h
	$(call msg,CC,,$@)
	$(Q)$(CC) $(CFLAGS) -c $(filter %.c,$^) $(LDLIBS) -o $@

$(OUTPUT)/%: $(OUTPUT)/%.o
	$(call msg,BINARY,,$@)
	$(Q)$(LINK.c) $^ $(LDLIBS) -o $@

EXTRA_CLEAN += $(OUTPUT)/*.o
