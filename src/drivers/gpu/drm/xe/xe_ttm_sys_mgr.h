/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2023 Intel Corporation
 */

#ifndef _XE_TTM_SYS_MGR_H_
#define _XE_TTM_SYS_MGR_H_

#include <linux/types.h>

struct xe_device;

int xe_ttm_sys_mgr_init(struct xe_device *xe);
u64 xe_ttm_sys_mgr_usage(struct xe_device *xe);

#endif
