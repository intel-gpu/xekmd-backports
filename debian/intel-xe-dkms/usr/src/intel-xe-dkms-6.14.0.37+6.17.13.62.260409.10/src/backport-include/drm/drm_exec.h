/* SPDX-License-Identifier: GPL-2.0 OR MIT */
#ifndef __BACKPORT_DRM_EXEC_H
#define __BACKPORT_DRM_EXEC_H

#include_next <drm/drm_exec.h>

#ifdef BPM_DRM_EXEC_INIT_ARG3_NOT_PRESENT
#define drm_exec_init(a,b,c) drm_exec_init(a,b)
#endif

#endif /* __BACKPORT_DRM_EXEC_H */
