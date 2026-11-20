/* SPDX-License-Identifier: GPL-2.0 OR MIT */
#ifndef __BACKPORT_DRM_GEM_H
#define __BACKPORT_DRM_GEM_H

#include_next <drm/drm_gem.h>

#ifdef BPM_DMA_RESV_USAGE_NOT_PRESENT
/* Recover tagged dma_resv fence-list pointers before generic teardown runs. */
#define drm_gem_object_release LINUX_BACKPORT(drm_gem_object_release)
void drm_gem_object_release(struct drm_gem_object *obj);
#endif

#endif /* __BACKPORT_DRM_GEM_H */
