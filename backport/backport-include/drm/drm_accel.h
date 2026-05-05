/* SPDX-License-Identifier: MIT */
#ifndef __BACKPORT_DRM_ACCEL_H__
#define __BACKPORT_DRM_ACCEL_H__

#include <linux/version.h>

/*
 * drm/drm_accel.h was introduced in v6.2.
 * For older kernels, this wrapper intentionally provides an empty fallback.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)
#include_next <drm/drm_accel.h>
#endif

#endif /* __BACKPORT_DRM_ACCEL_H__ */
