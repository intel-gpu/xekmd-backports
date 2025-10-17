#ifndef _BACKPORT_I915_DRM_H_
#define _BACKPORT_I915_DRM_H_

#ifndef HAVE_DRM_INTEL_I915_DRM_H
#include <drm/i915_drm.h>
#else
#include_next <drm/intel/i915_drm.h>
#endif

#endif /* _BACKPORT_I915_DRM_H_ */
