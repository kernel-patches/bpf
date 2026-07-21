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
TEST_GEN_PROGS += test_memcg_stat_cross_cpu
TEST_GEN_PROGS += test_memcontrol
TEST_GEN_PROGS += test_pids
TEST_GEN_PROGS += test_zswap

LOCAL_HDRS += $(selfdir)/clone3/clone3_selftests.h $(selfdir)/pidfd/pidfd.h

# test_memcg_stat_cross_cpu builds a BPF program + skeleton through lib.bpf.mk.
# OVERRIDE_TARGETS suppresses lib.mk's default C link rule (re-supplied below);
# it must be set before ../lib.mk is included.
BPF_SRCS         := memcg_stat_cross_cpu.bpf.c
OVERRIDE_TARGETS := 1

include ../lib.mk
include lib/libcgroup.mk
include ../lib.bpf.mk

# Re-supply the default C link rule that OVERRIDE_TARGETS removed, for the plain
# cgroup tests.  test_memcg_stat_cross_cpu has its own recipe further below.
LOCAL_HDRS += $(selfdir)/kselftest_harness.h $(selfdir)/kselftest.h
$(OUTPUT)/%: %.c $(LOCAL_HDRS)
	$(call msg,CC,,$@)
	$(Q)$(LINK.c) $(filter-out $(LOCAL_HDRS),$^) $(LDLIBS) -o $@

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

# test_memcg_stat_cross_cpu links cgroup_util and the generated BPF skeleton
# against the in-tree static libbpf that lib.bpf.mk built.
$(OUTPUT)/test_memcg_stat_cross_cpu: test_memcg_stat_cross_cpu.c \
					$(BPF_SKELS) $(LIBCGROUP_O)
	$(call bpf_link,$@,$< $(LIBCGROUP_O))
