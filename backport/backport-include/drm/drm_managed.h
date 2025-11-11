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

#ifdef BPM_DRMM_WORKQUEUE_RELEASE_NOT_PRESENT
void __drmm_workqueue_release(struct drm_device *device, void *wq);
#endif

#ifdef BPM_DRMM_ALLOC_ORDERED_WORKQUEUE_NOT_PRESENT
#define drmm_alloc_ordered_workqueue(dev, fmt, flags, args...)					\
	({											\
		struct workqueue_struct *wq = alloc_ordered_workqueue(fmt, flags, ##args);	\
		wq ? ({										\
			int ret = drmm_add_action_or_reset(dev, __drmm_workqueue_release, wq);	\
			ret ? ERR_PTR(ret) : wq;						\
		}) :										\
			wq;									\
	})
#endif

#endif /* __BACKPORT_DRM_BUDDY_H__ */
