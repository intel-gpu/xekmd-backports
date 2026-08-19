/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2022 Intel Corporation
 */

#ifndef _XE_DEBUGFS_H_
#define _XE_DEBUGFS_H_

#include <linux/types.h>

struct xe_device;

#ifdef CONFIG_DEBUG_FS
bool xe_fault_gt_reset(void);
bool xe_fault_csc_hw_error(void);
bool xe_fault_wedge_cold_reset(void);
void xe_debugfs_register(struct xe_device *xe);
#ifdef BPM_DRM_MINOR_DEBUGFS_SYMLINK_NOT_PRESENT
void xe_debugfs_cleanup_compat_structure(struct xe_device *xe);
#endif
#else
static inline bool xe_fault_gt_reset(void) { return false; }
static inline bool xe_fault_csc_hw_error(void) { return false; }
static inline bool xe_fault_wedge_cold_reset(void) { return false; }
static inline void xe_debugfs_register(struct xe_device *xe) { }
#ifdef BPM_DRM_MINOR_DEBUGFS_SYMLINK_NOT_PRESENT
static inline void xe_debugfs_cleanup_compat_structure(struct xe_device *xe) { }
#endif
#endif

#endif
