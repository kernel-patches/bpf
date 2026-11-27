TEST_KMOD_DIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
SRCTREE_KDIR := $(abspath $(TEST_KMOD_DIR)/../../../../..)
# Honor O=/KBUILD_OUTPUT only if they point at a prepared kernel build
# directory (one containing Module.symvers); otherwise treat the value as a
# selftests-only output directory and fall back to in-tree or distro headers.
# The parent bpf/Makefile resolves O=/KBUILD_OUTPUT to absolute paths before
# invoking this sub-make so relative paths still anchor to the user's
# invocation directory.
KMOD_O := $(or $(O),$(KBUILD_OUTPUT))
KMOD_O_VALID := $(if $(KMOD_O),$(if $(wildcard $(KMOD_O)/Module.symvers),$(KMOD_O)))
KDIR ?= $(if $(KMOD_O_VALID),$(SRCTREE_KDIR), \
	    $(if $(wildcard $(SRCTREE_KDIR)/Module.symvers),$(SRCTREE_KDIR), \
		/lib/modules/$(shell uname -r)/build))

# kbuild runs resolve_btfids with the flags which the config of the kernel asks
# for, and --fmodret_scan needs a resolve_btfids which is linked with LLVM. The
# one of the kernel build is. The one of the selftests, which bpf/Makefile passes
# down, is not. A kernel build directory that comes out of an archive can lack
# the tool: kbuild makes it again, in its place: not in the OUTPUT of kselftest.
KMOD_OBJTREE := $(or $(KMOD_O_VALID),$(KDIR))
KERNEL_RESOLVE_BTFIDS := $(KMOD_OBJTREE)/tools/bpf/resolve_btfids/resolve_btfids
ifneq ($(shell grep -sx CONFIG_BPF_FMODRET_SCAN=y $(KMOD_OBJTREE)/include/config/auto.conf),)
MAKEOVERRIDES := $(filter-out RESOLVE_BTFIDS=% OUTPUT=%,$(MAKEOVERRIDES))
all: $(KERNEL_RESOLVE_BTFIDS)
endif

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
	$(Q)$(MAKE) -C $(KDIR) $(if $(KMOD_O_VALID),O=$(KMOD_O_VALID) KBUILD_OUTPUT=$(KMOD_O_VALID),KBUILD_OUTPUT=) \
		M=$(TEST_KMOD_DIR) modules
else ifneq ("$(wildcard $(KDIR))", "")
	$(Q)$(MAKE) -C $(KDIR) $(if $(KMOD_O_VALID),O=$(KMOD_O_VALID) KBUILD_OUTPUT=$(KMOD_O_VALID),KBUILD_OUTPUT=) \
		M=$(TEST_KMOD_DIR) modules
endif

$(KERNEL_RESOLVE_BTFIDS):
	$(Q)$(MAKE) -C $(KDIR) $(if $(KMOD_O_VALID),O=$(KMOD_O_VALID) KBUILD_OUTPUT=$(KMOD_O_VALID),KBUILD_OUTPUT=) \
		tools/bpf/resolve_btfids

clean:
ifneq ("$(wildcard $(KDIR))", "")
	$(Q)$(MAKE) -C $(KDIR) $(if $(KMOD_O_VALID),O=$(KMOD_O_VALID) KBUILD_OUTPUT=$(KMOD_O_VALID),KBUILD_OUTPUT=) \
		M=$(TEST_KMOD_DIR) clean
endif
