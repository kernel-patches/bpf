TEST_KMOD_DIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
SRCTREE_KDIR := $(abspath $(TEST_KMOD_DIR)/../../../../..)
KDIR ?= $(if $(O),$(O),$(if $(KBUILD_OUTPUT),$(KBUILD_OUTPUT),$(if $(wildcard $(SRCTREE_KDIR)/Module.symvers),$(SRCTREE_KDIR),/lib/modules/$(shell uname -r)/build)))

ifeq ($(V),1)
Q =
else
Q = @
endif

MODULES = bpf_testmod.ko bpf_test_no_cfi.ko bpf_test_modorder_x.ko \
	bpf_test_modorder_y.ko bpf_test_rqspinlock.ko

$(foreach m,$(MODULES),$(eval obj-m += $(m:.ko=.o)))

CFLAGS_bpf_testmod.o = -I$(src)

# Ensure KDIR exists, otherwise skip module build and clean.
all:
ifneq ("$(wildcard $(KDIR))", "")
	$(Q)$(MAKE) -C $(KDIR) M=$(TEST_KMOD_DIR) modules
endif

clean:
ifneq ("$(wildcard $(KDIR))", "")
	$(Q)$(MAKE) -C $(KDIR) M=$(TEST_KMOD_DIR) clean
endif
