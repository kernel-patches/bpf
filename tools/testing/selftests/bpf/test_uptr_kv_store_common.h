#ifndef _TEST_UPTR_KV_STORE_COMMON_H
#define _TEST_UPTR_KV_STORE_COMMON_H

enum test_kvs_op {
	KVS_INT_GET,
	KVS_INT_PUT,
	KVS_STRUCT_GET,
	KVS_STRUCT_PUT,
};

struct test_struct {
	int a;
	int b;
};

struct test_struct_v1 {
	int a;
	int b;
	int c;
};

#endif
