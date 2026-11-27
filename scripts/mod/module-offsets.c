// SPDX-License-Identifier: GPL-2.0
/* Layout of the structures modpost emits into *.mod.S. */
#define COMPILE_OFFSETS
#include <linux/kbuild.h>
#include <linux/module.h>

int main(void)
{
	DEFINE(MOD_SIZEOF_LONG, sizeof(long));
	DEFINE(MOD_PREL32_RELOCATIONS, IS_ENABLED(CONFIG_HAVE_ARCH_PREL32_RELOCATIONS));
	DEFINE(MOD_FUNC_PLABEL, IS_ENABLED(CONFIG_PARISC) && IS_ENABLED(CONFIG_64BIT));

	DEFINE(MOD_SIZEOF_struct_module, sizeof(struct module));
	DEFINE(MOD_ALIGNOF_struct_module, __alignof__(struct module));
	OFFSET(MOD_OFF_module_name, module, name);
	OFFSET(MOD_OFF_module_init, module, init);
#ifdef CONFIG_MODULE_UNLOAD
	OFFSET(MOD_OFF_module_exit, module, exit);
#endif
#if defined(CONFIG_M68K) && defined(CONFIG_MMU)
	/* The only architecture whose .arch is not all zeroes. */
	OFFSET(MOD_OFF_module_arch_fixup_start, module, arch.fixup_start);
	OFFSET(MOD_OFF_module_arch_fixup_end, module, arch.fixup_end);
#endif
	DEFINE(MOD_NAME_LEN, MODULE_NAME_LEN);

	DEFINE(MOD_SIZEOF_struct_modversion_info, sizeof(struct modversion_info));
	DEFINE(MOD_ALIGNOF_struct_modversion_info, __alignof__(struct modversion_info));
	OFFSET(MOD_OFF_modversion_info_name, modversion_info, name);

	return 0;
}
