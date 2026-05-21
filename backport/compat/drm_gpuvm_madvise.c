// SPDX-License-Identifier: GPL-2.0-only

#include <drm/drm_gpuvm.h>
#include <drm/drm_gem.h>

#ifdef BPM_DRM_GPUVM_MADVISE_OPS_CREATE_NOT_PRESENT

/**
 * drm_gpuvm_madvise_ops_create() - creates the &drm_gpuva_ops to split
 * @gpuvm: the &drm_gpuvm representing the GPU VA space
 * @req: map request arguments
 *
 * This function creates a list of operations to perform splitting
 * of existent mapping(s) at start or end, based on the request map.
 *
 * Compatibility shim for kernels < 7.0 that have drm_gpuvm but are missing
 * drm_gpuvm_madvise_ops_create. Falls back to drm_gpuvm_sm_map_ops_create.
 *
 * Returns: a pointer to the &drm_gpuva_ops on success, an ERR_PTR on failure
 */
struct drm_gpuva_ops *
drm_gpuvm_madvise_ops_create(struct drm_gpuvm *gpuvm,
			     const struct drm_gpuvm_map_req *req)
{
	/* For kernels without madvise support, use the standard map ops */
	return drm_gpuvm_sm_map_ops_create(gpuvm, req);
}
EXPORT_SYMBOL_GPL(drm_gpuvm_madvise_ops_create);
#endif
