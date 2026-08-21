/* SPDX-License-Identifier: MIT */
#ifndef __BACKPORT_DRM_DRV_H__
#define __BACKPORT_DRM_DRV_H__

#include <linux/types.h>
#include_next <drm/drm_drv.h>

#ifndef BPM_DRV_DATE_NOT_PRESENT
#define DRIVER_DATE             "20201103"
#endif

#ifdef BPM_DRM_DEV_WEDGED_EVENT_NOT_PRESENT
int drm_dev_wedged_event(struct drm_device *dev, unsigned long method,
			struct drm_wedge_task_info *info);
#elif defined(BPM_DRM_DEV_WEDGED_EVENT_ARG3_NOT_PRESENT)
static inline int backport_drm_dev_wedged_event_arg3(struct drm_device *dev,
                        unsigned long method,
                        struct drm_wedge_task_info *info)
{
        (void)info;
        return drm_dev_wedged_event(dev, method);
}

#define drm_dev_wedged_event(_dev, _method, _info) \
        backport_drm_dev_wedged_event_arg3((_dev), (_method), (_info))
#endif

#ifndef DRIVER_GEM_GPUVA
#define DRIVER_GEM_GPUVA        (1U << 8)
#endif

#endif /* __BACKPORT_DRM_DRV_H__ */
