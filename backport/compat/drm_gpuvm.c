// SPDX-License-Identifier: GPL-2.0-only

#include <drm/drm_gpuvm.h>
#include <drm/drm_gem.h>

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
struct drm_gpuvm_bo *
drm_gpuvm_bo_obtain_locked(struct drm_gpuvm *gpuvm,
			   struct drm_gem_object *obj)
{
	struct drm_gpuvm_bo *vm_bo;

	/*
	 * In immediate mode this would require the caller to hold the GEMs
	 * gpuva mutex, but it's not okay to allocate while holding that lock,
	 * and this method allocates. Immediate mode drivers should use
	 * drm_gpuvm_bo_obtain_prealloc() instead.
	 */
	drm_WARN_ON(gpuvm->drm, drm_gpuvm_immediate_mode(gpuvm));

	vm_bo = drm_gpuvm_bo_find(gpuvm, obj);
	if (vm_bo)
		return vm_bo;

	vm_bo = drm_gpuvm_bo_create(gpuvm, obj);
	if (!vm_bo)
		return ERR_PTR(-ENOMEM);

	drm_gem_gpuva_assert_lock_held(gpuvm, obj);
	list_add_tail(&vm_bo->list.entry.gem, &obj->gpuva.list);

	return vm_bo;
}
EXPORT_SYMBOL_GPL(drm_gpuvm_bo_obtain_locked);
#endif
