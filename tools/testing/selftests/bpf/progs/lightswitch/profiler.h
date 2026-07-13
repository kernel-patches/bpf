#include "basic_types.h"

// Number of frames to walk per tail call iteration.
#define MAX_STACK_DEPTH_PER_PROGRAM 7
// Number of BPF tail calls that will be attempted.
#define MAX_TAIL_CALLS 30
// Maximum number of frames.
#define MAX_STACK_DEPTH 200
_Static_assert(MAX_TAIL_CALLS *MAX_STACK_DEPTH_PER_PROGRAM >= MAX_STACK_DEPTH,
               "enough iterations to traverse the whole stack");
// Number of unique stacks.
#define MAX_STACK_TRACES_ENTRIES 64000
// Number of items in the stack counts aggregation map.
#define MAX_STACK_COUNTS_ENTRIES 10240
// Maximum number of processes we are willing to track.
#define MAX_PROCESSES 5000
// Maximum number of memory mappings entries we can store in the LPM trie. This is shared across all
// the processes and assumes an average of 200 entries per process. These are LPM entries that in most
// cases will be higher than the number of mappings.
#define MAX_MAPPINGS MAX_PROCESSES * 200
// Binary search iterations to find unwind information.
#define MAX_BINARY_SEARCH_DEPTH 17
// Number of entries in the 'outer' unwind map.
#define MAX_OUTER_UNWIND_MAP_ENTRIES 3000

#define UNWIND_INFO_PAGE_BIT_LEN 16
#define UNWIND_INFO_PAGE_SIZE    (1 << UNWIND_INFO_PAGE_BIT_LEN)
#define PREVIOUS_PAGE(address)   (address - UNWIND_INFO_PAGE_SIZE)
_Static_assert(MAX_BINARY_SEARCH_DEPTH >= UNWIND_INFO_PAGE_BIT_LEN, "unwind table is big enough");
#define HIGH_PC_MASK  0x0000FFFFFFFF0000LLU
#define LOW_PC_MASK   0x000000000000FFFFLLU
#define HIGH_PC(addr) (addr & HIGH_PC_MASK)
#define LOW_PC(addr)  (addr & LOW_PC_MASK)

#define MAX_EXECUTABLE_TO_PAGE_ENTRIES 500 * 1000

#define MAPPING_TYPE_FILE 0
#define MAPPING_TYPE_ANON 1
#define MAPPING_TYPE_VDSO 2

typedef struct {
    u64 executable_id;
    u64 file_offset;
} page_key_t;

typedef struct {
    u32 low_index;
    u32 high_index;
} page_value_t;

// Values for the unwind table's CFA type.
#define CFA_TYPE_RBP                   1
#define CFA_TYPE_RSP                   2
#define CFA_TYPE_CFA_TYPE_UNSUP_EXP    3
#define CFA_TYPE_PLT1                  4
#define CFA_TYPE_PLT2                  5
#define CFA_TYPE_DEREF_AND_ADD         6
#define CFA_TYPE_END_OF_FDE_MARKER     7
#define CFA_TYPE_UNSUP_REGISTER_OFFSET 8  // not used in the unwinder yet.
#define CFA_TYPE_OFFSET_DID_NOT_FIT    9

// Values for the unwind table's frame pointer type.
#define RBP_TYPE_UNCHANGED                      0
#define RBP_TYPE_OFFSET                         1
#define RBP_TYPE_REGISTER                       2
#define RBP_TYPE_EXPRESSION                     3
#define RBP_TYPE_UNDEFINED_RETURN_ADDRESS       4
#define RBP_TYPE_OFFSET_DID_NOT_FIT             5
#define RBP_TYPE_ARM64_RETURN_ADDRESS_LR        6
#define RBP_TYPE_ARM64_RETURN_ADDRESS_FRAME     7
#define RBP_TYPE_ARM64_RETURN_ADDRESS_ELSEWHERE 8

// Binary search error codes.
#define BINARY_SEARCH_DEFAULT              0xFABADAFABADAULL
#define BINARY_SEARCH_SHOULD_NEVER_HAPPEN  0xDEADBEEFDEADBEEFULL
#define BINARY_SEARCH_EXHAUSTED_ITERATIONS 0xBADFADBADFADBADULL

struct lightswitch_config_t {
    bool verbose_logging;
    bool use_ring_buffers;
    bool use_task_pt_regs_helper;
    bool use_btf_helpers;
    unsigned int userspace_pid_ns_level;
};

struct unwinder_stats_t {
    u64 total;
    u64 success_dwarf;
    u64 error_truncated;
    u64 error_unsupported_expression;
    u64 error_unsupported_frame_pointer_action;
    u64 error_unsupported_cfa_register;
    u64 error_previous_rsp_read;
    u64 error_previous_rsp_zero;
    u64 error_previous_rip_read;
    u64 error_previous_rip_zero;
    u64 error_previous_rbp_read;
    u64 error_should_never_happen;
    u64 error_mapping_not_found;
    u64 error_mapping_does_not_contain_pc;
    u64 error_page_not_found;
    u64 error_binary_search_exhausted_iterations;
    u64 error_sending_new_process_event;
    u64 error_sending_need_unwind_info_event;
    u64 error_cfa_offset_did_not_fit;
    u64 error_rbp_offset_did_not_fit;
    u64 error_failure_sending_stack;
    u64 bp_non_zero_for_bottom_frame;
    u64 vdso_encountered;
    u64 jit_encountered;
};

const volatile struct lightswitch_config_t lightswitch_config = {
    .verbose_logging = false,
    .use_ring_buffers = false,
    .use_task_pt_regs_helper = false,
    .use_btf_helpers = false,
    .userspace_pid_ns_level = -1,
};

#define LOG(fmt, ...)                             \
    ({                                            \
        if (lightswitch_config.verbose_logging) { \
            bpf_printk(fmt, ##__VA_ARGS__);       \
        }                                         \
    })

// Represents an executable mapping.
typedef struct {
    u64 executable_id;
    u64 load_address;
    u64 begin;
    u64 end;
    u32 type;
} mapping_t;

// Key for the longest prefix matching. This is defined
// in the kernel in struct bpf_lpm_trie_key.
struct exec_mappings_key {
    u32 prefix_len;
    // Per /usr/include/bits/typesizes.h, __PID_T_TYPE is S32 (i32 in Rust)
    s32 pid;
    u64 data;
};

// Prefix size in bits, excluding the prefix length.
#define PREFIX_LEN (sizeof(struct exec_mappings_key) - sizeof(u32)) * 8;

typedef struct __attribute__((packed)) {
    u16 pc_low;
    u8 cfa_type;
    u8 rbp_type;
    u16 cfa_offset;
    s16 rbp_offset;
} stack_unwind_row_t;

_Static_assert(sizeof(stack_unwind_row_t) == 8,
               "unwind row has the expected size");

// The addresses of a native stack trace.
typedef struct {
    u32 ulen;
    u32 klen;
    // Needed as the verifier won't operate with dynamically computed offsets and
    // wants to ensure that any write won't be out of bounds. Note that only the
    // actual unwound stack will be sent to userspace.
    u64 addresses[MAX_STACK_DEPTH * 2];
} native_stack_t;

typedef struct {
    int pid;
    int tid;
    u64 collected_at;
    native_stack_t stack;
} sample_t;

typedef struct {
    unsigned long long ip;
    unsigned long long sp;
    unsigned long long bp;
    unsigned long long lr;
    u64 tail_calls;
    sample_t sample;
} unwind_state_t;

enum event_type {
    EVENT_NEW_PROCESS = 1,
    EVENT_NEED_UNWIND_INFO = 2,
};

typedef struct {
    enum event_type type;
    int pid;  // use right name here (tgid?)
    u64 address;
    // Not using char as it's signed in arm64.
    u8 comm[16];
} Event;

enum program {
    PROGRAM_NATIVE_UNWINDER = 0,
};
