/* SPDX-License-Identifier: GPL-2.0 OR MIT */

#include <drm/drm_suballoc.h>

#if defined(BPM_DRM_SUBALLOC_ALLOC_NOT_PRESENT) && !defined(CPTCFG_BUILD_XE_DRM_SUBALLOC_HELPER)
/**
 * drm_suballoc_alloc() - Allocate uninitialized suballoc object.
 * @gfp: gfp flags used for memory allocation.
 *
 * Allocate memory for an uninitialized suballoc object. Intended usage is
 * allocate memory for suballoc object outside of a reclaim tainted context
 * and then be initialized at a later time in a reclaim tainted context.
 *
 * @drm_suballoc_free() should be used to release the memory if returned
 * suballoc object is in uninitialized state.
 *
 * Return: a new uninitialized suballoc object, or an ERR_PTR(-ENOMEM).
 */
struct drm_suballoc *drm_suballoc_alloc(gfp_t gfp)
{
	return kmalloc(sizeof(struct drm_suballoc), gfp);
}
EXPORT_SYMBOL(drm_suballoc_alloc);

/**
 * drm_suballoc_insert() - Initialize a suballocation and insert a hole.
 * @sa_manager: pointer to the sa_manager
 * @sa: The struct drm_suballoc.
 * @size: number of bytes we want to suballocate.
 * @intr: Whether to perform waits interruptible. This should typically
 *        always be true, unless the caller needs to propagate a
 *        non-interruptible context from above layers.
 * @align: Alignment. Must not exceed the default manager alignment.
 *         If @align is zero, then the manager alignment is used.
 *
 * Try to make a suballocation on a pre-allocated suballoc object of size @size,
 * which will be rounded up to the alignment specified in specified in
 * drm_suballoc_manager_init().
 *
 * Return: zero on success, errno on failure.
 */
int drm_suballoc_insert(struct drm_suballoc_manager *sa_manager,
				      struct drm_suballoc *sa, size_t size,
				      bool intr, size_t align)
{
	struct drm_suballoc *tmp;

	tmp = drm_suballoc_new(sa_manager, size, GFP_NOIO, intr, align);
	if (IS_ERR(tmp))
		return PTR_ERR(tmp);

	/*
	 * Move tmp's list positions into sa, then free the temporary
	 * container.  After list_replace(), sa is in the manager's lists
	 * and tmp is no longer referenced by any list.
	 */
	list_replace(&tmp->olist, &sa->olist);
	list_replace(&tmp->flist, &sa->flist);
	sa->manager = tmp->manager;
	sa->soffset = tmp->soffset;
	sa->eoffset = tmp->eoffset;
	sa->fence   = tmp->fence;

	kfree(tmp);
	return 0;
}
EXPORT_SYMBOL(drm_suballoc_insert);

#endif /*#if defined(BPM_DRM_SUBALLOC_ALLOC_NOT_PRESENT) && !defined(CPTCFG_BUILD_XE_DRM_SUBALLOC_HELPER) */
