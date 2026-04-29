#ifndef __BACKPORT_DRM_GPUVM_H
#define __BACKPORT_DRM_GPUVM_H

#include_next <drm/drm_gpuvm.h>

#ifdef BPM_DRM_GPUVM_BO_OBTAIN_LOCKED_NOT_PRESENT

/**
 * drm_gpuvm_bo_obtain_locked() - obtains an instance of the &drm_gpuvm_bo for
 * the given &drm_gpuvm and &drm_gem_object
 * @gpuvm: The &drm_gpuvm the @obj is mapped in.
 * @obj: The &drm_gem_object being mapped in the @gpuvm.
 *
 * Find the &drm_gpuvm_bo representing the combination of the given
 * &drm_gpuvm and &drm_gem_object. If found, increases the reference
 * count of the &drm_gpuvm_bo accordingly. If not found, allocates a new
 * &drm_gpuvm_bo.
 *
 * Requires the lock for the GEMs gpuva list.
 *
 * A new &drm_gpuvm_bo is added to the GEMs gpuva list.
 *
 * Returns: a pointer to the &drm_gpuvm_bo on success, an ERR_PTR on failure
 */
struct drm_gpuvm_bo * drm_gpuvm_bo_obtain_locked(struct drm_gpuvm *gpuvm,
			   struct drm_gem_object *obj);

#endif /* BPM_DRM_GPUVM_BO_OBTAIN_LOCKED_NOT_PRESENT */

#ifdef BPM_DRM_GPUVM_MADVISE_OPS_CREATE_NOT_PRESENT

struct drm_gpuva_ops *
drm_gpuvm_madvise_ops_create(struct drm_gpuvm *gpuvm,
			     const struct drm_gpuvm_map_req *req);

#endif /* BPM_DRM_GPUVM_MADVISE_OPS_CREATE_NOT_PRESENT */

#endif /* __BACKPORT_DRM_GPUVM_H */
