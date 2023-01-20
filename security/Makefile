# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the kernel security code
#

gen := include/generated
obj-$(CONFIG_KEYS)			+= keys/

# always enable default capabilities
obj-y					+= commoncap.o
obj-$(CONFIG_MMU)			+= min_addr.o

# Object file lists
obj-$(CONFIG_SECURITY)			+= security.o
obj-$(CONFIG_SECURITYFS)		+= inode.o
obj-$(CONFIG_SECURITY_SELINUX)		+= selinux/
obj-$(CONFIG_SECURITY_SMACK)		+= smack/
obj-$(CONFIG_SECURITY)			+= lsm_audit.o
obj-$(CONFIG_SECURITY_TOMOYO)		+= tomoyo/
obj-$(CONFIG_SECURITY_APPARMOR)		+= apparmor/
obj-$(CONFIG_SECURITY_YAMA)		+= yama/
obj-$(CONFIG_SECURITY_LOADPIN)		+= loadpin/
obj-$(CONFIG_SECURITY_SAFESETID)       += safesetid/
obj-$(CONFIG_SECURITY_LOCKDOWN_LSM)	+= lockdown/
obj-$(CONFIG_CGROUPS)			+= device_cgroup.o
obj-$(CONFIG_BPF_LSM)			+= bpf/
obj-$(CONFIG_SECURITY_LANDLOCK)		+= landlock/

# Object integrity file lists
obj-$(CONFIG_INTEGRITY)			+= integrity/

$(addprefix $(obj)/,$(obj-y)): $(gen)/lsm_count.h

quiet_cmd_lsm_count = GEN     ${gen}/lsm_count.h
      cmd_lsm_count = scripts/security/gen_lsm_count ${gen}/lsm_count.h

targets += lsm_count.h

${gen}/lsm_count.h: FORCE
	$(call if_changed,lsm_count)
