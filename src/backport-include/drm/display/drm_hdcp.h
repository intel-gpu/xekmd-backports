/* SPDX-License-Identifier: MIT */
#ifndef __BACKPORT_DRM_DISPLAY_DRM_HDCP_H__
#define __BACKPORT_DRM_DISPLAY_DRM_HDCP_H__

#ifdef HAVE_DRM_DISPLAY_DRM_HDCP_H
#include_next <drm/display/drm_hdcp.h>
#else
#include <drm/drm_hdcp.h>
#endif

#endif /* __BACKPORT_DRM_DISPLAY_DRM_HDCP_H__ */
