/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/*
 * Backport compatibility shim for drm_suballoc_alloc() and
 * drm_suballoc_insert() added in kernel 7.1.
 *
 * In 7.1 the single drm_suballoc_new() was split into two phases:
 *   drm_suballoc_alloc(gfp)               - allocate struct (no sleeping)
 *   drm_suballoc_insert(mgr, sa, ...)     - wait for a free slot and insert
 *
 * On 6.6 we emulate both using the existing drm_suballoc_new().
 */

#ifndef __BACKPORT_DRM_SUBALLOC_H__
#define __BACKPORT_DRM_SUBALLOC_H__

#include_next <drm/drm_suballoc.h>

#if defined(BPM_DRM_SUBALLOC_ALLOC_NOT_PRESENT) && !defined(CPTCFG_BUILD_XE_DRM_SUBALLOC_HELPER)

#include <linux/list.h>
#include <linux/slab.h>
#include <linux/err.h>

/**
 * drm_suballoc_alloc - Allocate an uninitialized suballoc object.
 * @gfp: GFP flags for the allocation.
 *
 * Backport: simply kmalloc the struct; drm_suballoc_insert() will fill
 * it in using the 6.6 drm_suballoc_new() internally.
 */
static inline struct drm_suballoc *drm_suballoc_alloc(gfp_t gfp)
{
	return kmalloc(sizeof(struct drm_suballoc), gfp);
}

/**
 * drm_suballoc_insert - Wait for a free slot and initialize a suballoc.
 * @sa_manager: the suballoc manager.
 * @sa:         pre-allocated (via drm_suballoc_alloc()) suballoc object.
 * @size:       requested size in bytes.
 * @intr:       whether to sleep interruptibly.
 * @align:      required alignment (0 = manager default).
 *
 * Backport: calls drm_suballoc_new() to do the blocking wait and slot
 * assignment, then moves the result into @sa and frees the temporary
 * allocation that drm_suballoc_new() created internally.
 */
static inline int drm_suballoc_insert(struct drm_suballoc_manager *sa_manager,
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

#endif /* BPM_DRM_SUBALLOC_ALLOC_NOT_PRESENT && !CPTCFG_BUILD_XE_DRM_SUBALLOC_HELPER */

#endif /* __BACKPORT_DRM_SUBALLOC_H__ */
