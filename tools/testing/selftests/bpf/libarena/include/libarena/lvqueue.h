/* SPDX-License-Identifier: LGPL-2.1 OR BSD-2-Clause */

#pragma once

struct lv_arr;

#define LV_ARR_BASESZ 128
#define LV_ARR_ORDERS 10

struct lv_arr {
	u64 __arena *data;
	u64 order;
};

typedef volatile struct lv_arr __arena lv_arr_t;

struct lv_queue {
	lv_arr_t *cur;
	volatile u64 top;
	volatile u64 bottom;
	struct lv_arr arr[LV_ARR_ORDERS];
};

typedef struct lv_queue __arena lv_queue_t;

int lvq_owner_push(lv_queue_t *lvq, u64 val);
int lvq_owner_pop(lv_queue_t *lvq, u64 *val);
int lvq_steal(lv_queue_t *lvq, u64 *val);

u64 lvq_create_internal(void);
#define lvq_create() ((lv_queue_t *)lvq_create_internal())

int lvq_destroy(lv_queue_t *lvq);
