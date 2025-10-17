/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2022 Intel Corporation
 */

#ifndef _XE_GT_PAGEFAULT_H_
#define _XE_GT_PAGEFAULT_H_

#include <linux/types.h>

struct xe_gt;
struct xe_guc;
struct xe_vm;

int xe_gt_pagefault_init(struct xe_gt *gt);
void xe_gt_pagefault_reset(struct xe_gt *gt);
int xe_guc_pagefault_handler(struct xe_guc *guc, u32 *msg, u32 len);
int xe_guc_access_counter_notify_handler(struct xe_guc *guc, u32 *msg, u32 len);
struct xe_vma *xe_gt_pagefault_lookup_vma(struct xe_vm *vm, u64 page_addr);

#endif	/* _XE_GT_PAGEFAULT_ */
