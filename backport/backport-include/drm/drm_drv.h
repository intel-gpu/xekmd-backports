/* SPDX-License-Identifier: MIT */
#ifndef __BACKPORT_DRM_DRV_H__
#define __BACKPORT_DRM_DRV_H__

#include <linux/types.h>
#include_next <drm/drm_drv.h>

#ifndef BPM_DRV_DATE_NOT_PRESENT
#define DRIVER_DATE             "20201103"
#endif

#ifdef BPM_DRMM_CGROUP_REGISTER_REGION_NOT_PRESENT
#include <linux/cgroup_dmem.h>
#include <drm/drm_managed.h>
#include <linux/slab.h>

static inline struct dmem_cgroup_region *drmm_cgroup_register_region(
	struct drm_device *dev, const char *region_name, u64 size)
{
	/* 
	 * Return NULL to indicate cgroup functionality is not available.
	 * This disables cgroup memory tracking but allows the driver to work.
	 */
	return NULL;
}
#endif /* BPM_DRMM_CGROUP_REGISTER_REGION_NOT_PRESENT */

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
