#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

#if __clang_major__ >= 18

SEC("?tc")
__log_level(2)
int test_verifier_range(void)
{
    asm volatile (
        "r5 = 100; \
        r5 /= 3; \
        w5 >>= 7; \
        r5 &= -386969681; \
        r5 -= -884670597; \
        w0 = w5; \
        if w0 & 0x894b6a55 goto +2; \
        r2 = 1; \
        r2 = 1; \
        r0 = 0; \
        "
    );
    return 0;
}

char _license[] SEC("license") = "GPL";

#endif
