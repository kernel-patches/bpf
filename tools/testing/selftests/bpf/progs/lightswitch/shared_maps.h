#ifndef __LIGHTSWITCH_SHARED_BPF_MAPS__
#define __LIGHTSWITCH_SHARED_BPF_MAPS__

#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct exec_mappings_key);
    __type(value, mapping_t);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, MAX_MAPPINGS);
} exec_mappings SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct unwinder_stats_t);
} percpu_stats SEC(".maps");

#define DEFINE_COUNTER(__func__name)                   \
    static void bump_unwind_##__func__name() {         \
        u32 zero = 0;                                  \
        struct unwinder_stats_t *unwinder_stats =      \
            bpf_map_lookup_elem(&percpu_stats, &zero); \
        if (unwinder_stats != NULL) {                  \
            unwinder_stats->__func__name++;            \
        }                                              \
    }

DEFINE_COUNTER(total);
DEFINE_COUNTER(success_dwarf);
DEFINE_COUNTER(error_truncated);
DEFINE_COUNTER(error_unsupported_expression);
DEFINE_COUNTER(error_unsupported_frame_pointer_action);
DEFINE_COUNTER(error_unsupported_cfa_register);
DEFINE_COUNTER(error_previous_rsp_read);
DEFINE_COUNTER(error_previous_rsp_zero);
DEFINE_COUNTER(error_previous_rip_read);
DEFINE_COUNTER(error_previous_rip_zero);
DEFINE_COUNTER(error_previous_rbp_read);
DEFINE_COUNTER(error_should_never_happen);
DEFINE_COUNTER(error_mapping_not_found);
DEFINE_COUNTER(error_mapping_does_not_contain_pc);
DEFINE_COUNTER(error_page_not_found);
DEFINE_COUNTER(error_binary_search_exhausted_iterations);
DEFINE_COUNTER(error_sending_new_process_event);
DEFINE_COUNTER(error_sending_need_unwind_info_event);
DEFINE_COUNTER(error_cfa_offset_did_not_fit);
DEFINE_COUNTER(error_rbp_offset_did_not_fit);
DEFINE_COUNTER(error_failure_sending_stack);
#ifdef __TARGET_ARCH_x86
DEFINE_COUNTER(bp_non_zero_for_bottom_frame);
#endif
DEFINE_COUNTER(vdso_encountered);
DEFINE_COUNTER(jit_encountered);

#endif
