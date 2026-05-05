/* SPDX-License-Identifier: MIT */
#ifndef __BACKPORT_DRM_PRIVACY_SCREEN_MACHINE_H__
#define __BACKPORT_DRM_PRIVACY_SCREEN_MACHINE_H__

#include <linux/version.h>

/*
 * drm/drm_privacy_screen_machine.h was introduced in v5.17.
 * For older kernels, an empty wrapper is sufficient for current users.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
#include_next <drm/drm_privacy_screen_machine.h>
#endif

#endif /* __BACKPORT_DRM_PRIVACY_SCREEN_MACHINE_H__ */
