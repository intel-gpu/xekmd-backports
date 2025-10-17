/*
 * Copyright © 2024 Intel Corporation
 */

#ifndef __BACKPORT_DRM_BUDDY_H__
#define __BACKPORT_DRM_BUDDY_H__

#include_next <drm/drm_buddy.h>

#ifdef BPM_DRM_BUDDY_FREE_LIST_ARG3_NOT_PRESENT
#define drm_buddy_free_list(x,y,z) drm_buddy_free_list(x,y)
#endif

#endif /* __BACKPORT_DRM_BUDDY_H__ */
