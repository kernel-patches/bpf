TEST_KMOD_DIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
SRCTREE_KDIR := $(abspath $(TEST_KMOD_DIR)/../../../../..)
KMOD_O := $(or $(O),$(KBUILD_OUTPUT))
KDIR ?= $(if $(KMOD_O),$(SRCTREE_KDIR),$(if $(wildcard $(SRCTREE_KDIR)/Module.symvers),$(SRCTREE_KDIR),/lib/modules/$(shell uname -r)/build))

ifeq ($(V),1)
Q =
else
Q = @
endif

MODULES = bpf_testmod.ko bpf_test_no_cfi.ko bpf_test_modorder_x.ko \
	bpf_test_modorder_y.ko bpf_test_rqspinlock.ko

$(foreach m,$(MODULES),$(eval obj-m += $(m:.ko=.o)))

CFLAGS_bpf_testmod.o = -I$(src)

# When BPF_STRICT_BUILD != 0, a missing KDIR is fatal (the default).
# When permissive, skip silently.
PERMISSIVE := $(filter 0,$(BPF_STRICT_BUILD))

all:
ifeq ($(PERMISSIVE),)
	$(Q)$(MAKE) -C $(KDIR) $(if $(KMOD_O),O=$(KMOD_O),KBUILD_OUTPUT=) \
		M=$(TEST_KMOD_DIR) modules
else ifneq ("$(wildcard $(KDIR))", "")
	$(Q)$(MAKE) -C $(KDIR) $(if $(KMOD_O),O=$(KMOD_O),KBUILD_OUTPUT=) \
		M=$(TEST_KMOD_DIR) modules
endif

clean:
ifeq ($(PERMISSIVE),)
	$(Q)$(MAKE) -C $(KDIR) $(if $(KMOD_O),O=$(KMOD_O),KBUILD_OUTPUT=) \
		M=$(TEST_KMOD_DIR) clean
else ifneq ("$(wildcard $(KDIR))", "")
	$(Q)$(MAKE) -C $(KDIR) $(if $(KMOD_O),O=$(KMOD_O),KBUILD_OUTPUT=) \
		M=$(TEST_KMOD_DIR) clean
endif
