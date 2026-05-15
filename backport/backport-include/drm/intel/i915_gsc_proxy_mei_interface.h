#ifndef _BACKPORT_I915_GSC_PROXY_MEI_INTERFACE_H_
#define _BACKPORT_I915_GSC_PROXY_MEI_INTERFACE_H_

#if defined(HAVE_DRM_INTEL_I915_GSC_PROXY_MEI_INTERFACE_H)
#include_next <drm/intel/i915_gsc_proxy_mei_interface.h>
#elif defined(HAVE_DRM_I915_GSC_PROXY_MEI_INTERFACE_H)
#include <drm/i915_gsc_proxy_mei_interface.h>
#else

#include <linux/types.h>

struct device;
struct module;

struct i915_gsc_proxy_component_ops {
	struct module *owner;
	int (*send)(struct device *dev, const void *buf, size_t size);
	int (*recv)(struct device *dev, void *buf, size_t size);
};

struct i915_gsc_proxy_component {
	struct device *mei_dev;
	const struct i915_gsc_proxy_component_ops *ops;
};

#endif

#endif /* _BACKPORT_I915_GSC_PROXY_MEI_INTERFACE_H_ */
