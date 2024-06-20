# SPDX-License-Identifier: GPL-2.0-or-later

quiet_cmd_gen_ftrace_pfe_stubs = FTRACE  $@
      cmd_gen_ftrace_pfe_stubs = $< $(objtree)/vmlinux.o $@

targets += .arch.vmlinux.o
.arch.vmlinux.o: $(srctree)/arch/powerpc/tools/gen-ftrace-pfe-stubs.sh $(objtree)/vmlinux.o FORCE
	$(call if_changed,gen_ftrace_pfe_stubs)

clean-files += $(objtree)/.arch.vmlinux.S $(objtree)/.arch.vmlinux.o
