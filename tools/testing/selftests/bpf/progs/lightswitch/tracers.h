#include "basic_types.h"

enum tracer_event_type {
    TRACER_EVENT_TYPE_PROCESS_EXIT = 1,
    TRACER_EVENT_TYPE_MUNMAP = 2,
};

typedef struct {
    u32 type;
    int pid;
    u64 start_address;
    u64 end_address;
} tracer_event_t;
