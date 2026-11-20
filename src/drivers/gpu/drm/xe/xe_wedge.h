/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2026 Intel Corporation
 */

#ifndef _XE_WEDGE_H_
#define _XE_WEDGE_H_

#include <linux/atomic.h>
#include <linux/types.h>

#include "xe_device_types.h"
#include "xe_wedge_types.h"

static inline bool xe_wedged(struct xe_device *xe)
{
	return atomic_read(&xe->wedged.flag);
}

static inline bool xe_wedge_mode_is_no_reset(struct xe_device *xe)
{
	return xe->wedged.mode == XE_WEDGED_MODE_UPON_ANY_HANG_NO_RESET;
}

void xe_wedge_declare(struct xe_device *xe, unsigned long method);
int xe_wedge_init(struct xe_device *xe);
int xe_wedge_set_mode(struct xe_device *xe, enum xe_wedged_mode mode);

#endif
