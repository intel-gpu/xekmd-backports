/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2022 Intel Corporation
 */

#ifndef _XE_DEBUGFS_H_
#define _XE_DEBUGFS_H_

struct xe_device;

#ifdef CONFIG_DEBUG_FS
void xe_debugfs_register(struct xe_device *xe);
#ifdef BPM_DRM_MINOR_DEBUGFS_SYMLINK_NOT_PRESENT
void xe_debugfs_cleanup_compat_structure(struct xe_device *xe);
#endif
#else
static inline void xe_debugfs_register(struct xe_device *xe) { }
#ifdef BPM_DRM_MINOR_DEBUGFS_SYMLINK_NOT_PRESENT
static inline void xe_debugfs_cleanup_compat_structure(struct xe_device *xe) { }
#endif
#endif

#endif
