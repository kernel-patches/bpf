# SPDX-License-Identifier: GPL-2.0
TEST_GEN_PROGS_EXTENDED = sample_umd.ko

$(OUTPUT)/%.ko: $(wildcard sample_umd/Makefile sample_umd/*.[ch])
	$(call msg,MOD,,$@)
	$(Q)$(MAKE) -C sample_umd install

OVERRIDE_TARGETS := 1
override define CLEAN
	$(call msg,CLEAN)
	$(Q)$(MAKE) -C sample_umd clean
endef

include ../lib.mk
