#ifndef __BACKPORT_DRM_GPUVM_H
#define __BACKPORT_DRM_GPUVM_H

#if defined(BPM_DRM_GPUVM_SM_MAP_OPS_CREATE_MAP_REQ_NOT_PRESENT) && \
	!IS_ENABLED(CPTCFG_DRM_GPUVM)
#define drm_gpuvm_sm_map_ops_create __hidden_drm_gpuvm_sm_map_ops_create
#endif

#include_next <drm/drm_gpuvm.h>

#if defined(BPM_DRM_GPUVM_SM_MAP_OPS_CREATE_MAP_REQ_NOT_PRESENT) && \
	!IS_ENABLED(CPTCFG_DRM_GPUVM)
#undef drm_gpuvm_sm_map_ops_create

struct drm_gpuva_ops *
drm_gpuvm_sm_map_ops_create(struct drm_gpuvm *gpuvm, u64 addr, u64 range,
			    struct drm_gem_object *obj, u64 offset);
#endif

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

/*
 * drm_gpuvm_sm_map_ops_create() signature compatibility.
 *
 * When the host kernel exposes the legacy 5-argument API (and we are not
 * building the backported drm_gpuvm), keep the caller name unchanged and
 * unpack the map_req into the legacy arguments via an internal helper.
 */
#if defined(BPM_DRM_GPUVM_SM_MAP_OPS_CREATE_MAP_REQ_NOT_PRESENT) && \
	!IS_ENABLED(CPTCFG_DRM_GPUVM)
static inline struct drm_gpuva_ops *
backport_drm_gpuvm_sm_map_ops_create(struct drm_gpuvm *gpuvm,
				     const struct drm_gpuvm_map_req *req)
{
	return drm_gpuvm_sm_map_ops_create(gpuvm, req->map.va.addr,
					   req->map.va.range,
					   req->map.gem.obj,
					   req->map.gem.offset);
}

#define drm_gpuvm_sm_map_ops_create(_gpuvm, _req) \
	backport_drm_gpuvm_sm_map_ops_create((_gpuvm), (_req))
#endif

#endif /* __BACKPORT_DRM_GPUVM_H */
