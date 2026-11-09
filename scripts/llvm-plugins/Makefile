# SPDX-License-Identifier: GPL-2.0-only

always-y += $(LLVM_PLUGIN)
targets += $(LLVM_PLUGIN)
clean-files += *.so

# Run llvm-config only to build a plugin, not when this Makefile is parsed
llvm_cxxflags = $(shell $(LLVM_CONFIG) --cxxflags)
llvm_ldflags = $(shell $(LLVM_CONFIG) --ldflags)

quiet_cmd_llvm_plugin = HOSTCXX $@
      cmd_llvm_plugin = $(HOSTCXX) -Wp,-MD,$(depfile) $(KBUILD_HOSTCXXFLAGS) \
		$(llvm_cxxflags) -fPIC -shared $(KBUILD_HOSTLDFLAGS) -o $@ $< \
		$(llvm_ldflags)

$(obj)/%.so: $(src)/%.cpp FORCE
	$(call if_changed_dep,llvm_plugin)

$(obj)/../../include/generated/llvm-plugins.h: $(addprefix $(obj)/, $(LLVM_PLUGIN)) FORCE
	$(call if_changed,touch)
always-y += ../../include/generated/llvm-plugins.h
