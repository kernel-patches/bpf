# SPDX-License-Identifier: GPL-2.0
obj-$(CONFIG_BPF_INSN_KFUNCS) += bpf_insn_kfuncs.o
ifeq ($(CONFIG_BPF_INSN_KFUNCS_ARCH),y)
CFLAGS_bpf_insn_kfuncs.o += -I$(src)/$(SRCARCH)
endif
