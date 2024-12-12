#ifndef _BACKPORT_I915_GSC_PROXY_MEI_INTERFACE_H_
#define _BACKPORT_I915_GSC_PROXY_MEI_INTERFACE_H_

#ifdef HAVE_DRM_I915_GSC_PROXY_MEI_INTERFACE_H
#include <drm/i915_gsc_proxy_mei_interface.h>
#else
#include_next <drm/intel/i915_gsc_proxy_mei_interface.h>
#endif

#endif /* _BACKPORT_I915_GSC_PROXY_MEI_INTERFACE_H_ */
