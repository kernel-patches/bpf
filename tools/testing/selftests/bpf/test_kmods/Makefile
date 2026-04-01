TEST_KMOD_DIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
SRCTREE_KDIR := $(abspath $(TEST_KMOD_DIR)/../../../../..)
# Prefer an explicit O= build output directory if specified. Otherwise use the
# in-tree kernel build when it has been configured, and fall back to the
# running kernel's module build directory for distribution kernel builds.
KDIR ?= $(if $(O),$(O),$(if $(wildcard $(SRCTREE_KDIR)/.config),$(SRCTREE_KDIR),/lib/modules/$(shell uname -r)/build))

ifeq ($(V),1)
Q =
else
Q = @
endif

MODULES = bpf_testmod.ko bpf_test_no_cfi.ko bpf_test_modorder_x.ko \
	bpf_test_modorder_y.ko bpf_test_rqspinlock.ko

$(foreach m,$(MODULES),$(eval obj-m += $(m:.ko=.o)))

CFLAGS_bpf_testmod.o = -I$(src)

all:
	$(Q)$(MAKE) -C $(KDIR) M=$(TEST_KMOD_DIR) modules

clean:
	$(Q)$(MAKE) -C $(KDIR) M=$(TEST_KMOD_DIR) clean
