#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

extern bool CONFIG_BPF_JIT_ALWAYS_ON __kconfig __weak;

/* This function is here to have CONFIG_BPF_JIT_ALWAYS_ON
 * used and added to object BTF.
 */
int unused(void)
{
	return CONFIG_BPF_JIT_ALWAYS_ON ? 0 : 1;
}
