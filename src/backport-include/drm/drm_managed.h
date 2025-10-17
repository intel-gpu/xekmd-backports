/* SPDX-License-Identifier: MIT */
/*
 * Copyright _ 2021 Intel Corporation
 */

#ifndef __BACKPORT_DRM_MANAGED_H__
#define __BACKPORT_DRM_MANAGED_H__

#include <drm/drm_buddy.h>
#include_next <drm/drm_managed.h>

#ifdef BPM_DRM_BUDDY_BLOCK_TRIM_2ND_ARG_NOT_PRESENT
#define drm_buddy_block_trim(a,b,c,d) drm_buddy_block_trim(a,c,d)
#endif

#endif /* __BACKPORT_DRM_BUDDY_H__ */
