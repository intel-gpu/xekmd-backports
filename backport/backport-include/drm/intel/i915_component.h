#ifndef _BACKPORT_I915_COMPONENT_H_
#define _BACKPORT_I915_COMPONENT_H_

#ifdef HAVE_DRM_I915_COMPONENT_H
#include <drm/i915_component.h>
#else
#include_next <drm/intel/i915_component.h>
#endif

#endif /* _BACKPORT_I915_COMPONENT_H_ */
