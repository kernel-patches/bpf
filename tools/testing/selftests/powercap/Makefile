# SPDX-License-Identifier: GPL-2.0

# User-space test script
TEST_PROGS := powercap_hierarchy.sh

KERNEL_SRC := $(realpath ../../../..)
KERNEL_OUTPUT := $(or $(O),$(KBUILD_OUTPUT))
# The selftests parent exports BUILD as <absolute kernel output>/kselftest.
# Use it when clean inherits a relative O= through MAKEFLAGS.
KDIR ?= $(if $(KERNEL_OUTPUT),$(if $(BUILD),$(BUILD)/..,$(if $(filter /%,$(KERNEL_OUTPUT)),$(KERNEL_OUTPUT),$(KERNEL_SRC)/$(KERNEL_OUTPUT))),$(KERNEL_SRC))
KERNEL_BUILD := $(abspath $(KDIR))

-include $(KERNEL_BUILD)/include/config/auto.conf

ifeq ($(CONFIG_POWERCAP)$(CONFIG_MODULES)$(CONFIG_MODULE_UNLOAD),yyy)
ifneq ($(wildcard $(KERNEL_BUILD)/Module.symvers),)
TEST_GEN_FILES := powercap_hierarchy.ko
endif
endif

.DEFAULT_GOAL := all

include ../lib.mk

ifeq ($(TEST_GEN_FILES),)
all:
	@echo "SKIP: powercap module needs CONFIG_POWERCAP, CONFIG_MODULES, CONFIG_MODULE_UNLOAD and a full kernel build"
endif

.PHONY: modules

$(OUTPUT)/powercap_hierarchy.ko: modules

modules:
	$(MAKE) -C $(KERNEL_BUILD) O=$(KERNEL_BUILD) KBUILD_OUTPUT=$(KERNEL_BUILD) \
		M=$(CURDIR) MO=$(abspath $(OUTPUT)) modules

.PHONY: clean_modules

clean: clean_modules

clean_modules:
	@if [ -f "$(KERNEL_BUILD)/Makefile" ] && [ -d "$(OUTPUT)" ]; then \
		$(MAKE) -C $(KERNEL_BUILD) O=$(KERNEL_BUILD) KBUILD_OUTPUT=$(KERNEL_BUILD) \
			M=$(CURDIR) MO=$(abspath $(OUTPUT)) clean; \
	fi
