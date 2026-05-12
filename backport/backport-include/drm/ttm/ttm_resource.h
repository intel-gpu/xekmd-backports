/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BACKPORT_DRM_TTM_RESOURCE_H__
#define __BACKPORT_DRM_TTM_RESOURCE_H__

#include_next <drm/ttm/ttm_resource.h>

#ifndef TTM_NUM_MEM_TYPES
#define TTM_NUM_MEM_TYPES 8
#endif

#endif /* __BACKPORT_DRM_TTM_RESOURCE_H__ */
