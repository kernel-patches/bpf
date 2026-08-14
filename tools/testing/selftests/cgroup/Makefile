# SPDX-License-Identifier: GPL-2.0
CFLAGS += -Wall -pthread

all: ${HELPER_PROGS}

TEST_FILES     := with_stress.sh
TEST_PROGS     := test_stress.sh test_cpuset_prs.sh test_cpuset_v1_hp.sh
TEST_GEN_FILES := wait_inotify
# Keep the lists lexicographically sorted
TEST_GEN_PROGS  = test_core
TEST_GEN_PROGS += test_cpu
TEST_GEN_PROGS += test_cpuset
TEST_GEN_PROGS += test_freezer
TEST_GEN_PROGS += test_hugetlb_memcg
TEST_GEN_PROGS += test_kill
TEST_GEN_PROGS += test_kmem
TEST_GEN_PROGS += test_memcontrol
TEST_GEN_PROGS += test_pids
TEST_GEN_PROGS += test_zswap

LOCAL_HDRS += $(selfdir)/clone3/clone3_selftests.h $(selfdir)/pidfd/pidfd.h

# test_memcg_stat_cross_cpu needs clang and a vmlinux with BTF; build it only
# where both exist, since every other test here needs just a C compiler.
# lib.mk settles CLANG from LLVM=, but not before OVERRIDE_TARGETS is needed.
ifneq ($(filter %/,$(LLVM)),)
CLANG ?= $(LLVM)clang
else
CLANG ?= clang$(filter -%,$(LLVM))
endif
READELF ?= $(CROSS_COMPILE)readelf
VMLINUX_BTF_PATHS ?= $(if $(O),$(O)/vmlinux)				\
		     $(if $(KBUILD_OUTPUT),$(KBUILD_OUTPUT)/vmlinux)	\
		     ../../../../vmlinux				\
		     /sys/kernel/btf/vmlinux				\
		     /boot/vmlinux-$(shell uname -r)
# A vmlinux built without CONFIG_DEBUG_INFO_BTF has nothing to dump, and taking
# it would fail this whole directory rather than just skip the BPF test.  Pick
# the first candidate that carries BTF; /sys/kernel/btf/vmlinux is raw BTF
# rather than an ELF file, so it needs no check.
VMLINUX_BTF ?= $(abspath $(firstword $(foreach v,$(wildcard $(VMLINUX_BTF_PATHS)),\
		 $(if $(filter /sys/kernel/btf/%,$(v)),$(v),\
		   $(if $(shell $(READELF) -S "$(v)" 2>/dev/null | grep -F .BTF),$(v))))))
# Either of the two knobs lib.bpf.mk takes instead of a vmlinux will do.
HAVE_BPF := $(and $(or $(VMLINUX_H),$(VMLINUX_BTF)),			\
		  $(shell command -v $(CLANG) 2>/dev/null))

ifneq ($(HAVE_BPF),)
TEST_GEN_PROGS += test_memcg_stat_cross_cpu
BPF_SRCS := memcg_stat_cross_cpu.bpf.c
# Suppresses lib.mk's default C link rule, re-supplied below.
OVERRIDE_TARGETS := 1
endif

include ../lib.mk
include lib/libcgroup.mk

ifneq ($(HAVE_BPF),)
include ../lib.bpf.mk

# The default link rule for the plain tests, which OVERRIDE_TARGETS removed.
LOCAL_HDRS += $(selfdir)/kselftest_harness.h $(selfdir)/kselftest.h
$(OUTPUT)/%: %.c $(LOCAL_HDRS)
	$(call msg,CC,,$@)
	$(Q)$(LINK.c) $(filter-out $(LOCAL_HDRS),$^) $(LDLIBS) -o $@
endif

$(OUTPUT)/test_core: $(LIBCGROUP_O)
$(OUTPUT)/test_cpu: $(LIBCGROUP_O)
$(OUTPUT)/test_cpuset: $(LIBCGROUP_O)
$(OUTPUT)/test_freezer: $(LIBCGROUP_O)
$(OUTPUT)/test_hugetlb_memcg: $(LIBCGROUP_O)
$(OUTPUT)/test_kill: $(LIBCGROUP_O)
$(OUTPUT)/test_kmem: $(LIBCGROUP_O)
$(OUTPUT)/test_memcontrol: $(LIBCGROUP_O)
$(OUTPUT)/test_pids: $(LIBCGROUP_O)
$(OUTPUT)/test_zswap: $(LIBCGROUP_O)

ifneq ($(HAVE_BPF),)
# Links cgroup_util and the skeleton against the libbpf lib.bpf.mk built.  The
# uapi include is private to this binary: the other tests here must keep
# resolving <linux/*.h> against the system headers.
$(OUTPUT)/test_memcg_stat_cross_cpu: private CFLAGS += -I$(top_srcdir)/tools/include/uapi
$(OUTPUT)/test_memcg_stat_cross_cpu: test_memcg_stat_cross_cpu.c \
					$(BPF_SKELS) $(LIBCGROUP_O) $(BPFOBJ)
	$(call bpf_link,$@,$< $(LIBCGROUP_O))
endif
