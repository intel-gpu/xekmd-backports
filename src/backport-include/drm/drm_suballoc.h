/* SPDX-License-Identifier: GPL-2.0 OR MIT */

#ifndef __BACKPORT_DRM_SUBALLOC_H__
#define __BACKPORT_DRM_SUBALLOC_H__

#include_next <drm/drm_suballoc.h>

#if defined(BPM_DRM_SUBALLOC_ALLOC_NOT_PRESENT) && !defined(CPTCFG_BUILD_XE_DRM_SUBALLOC_HELPER)
struct drm_suballoc *drm_suballoc_alloc(gfp_t gfp);
int drm_suballoc_insert(struct drm_suballoc_manager *sa_manager,
				      struct drm_suballoc *sa, size_t size,
				      bool intr, size_t align);
#endif /* BPM_DRM_SUBALLOC_ALLOC_NOT_PRESENT && !CPTCFG_BUILD_XE_DRM_SUBALLOC_HELPER */

#endif /* __BACKPORT_DRM_SUBALLOC_H__ */
