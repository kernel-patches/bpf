/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2023. Huawei Technologies Co., Ltd
 */
#ifndef __BPF_INTERNAL_H_
#define __BPF_INTERNAL_H_

struct btf_record;

void __bpf_obj_drop_impl(void *p, const struct btf_record *rec, bool percpu);

#endif /* __BPF_INTERNAL_H_ */
