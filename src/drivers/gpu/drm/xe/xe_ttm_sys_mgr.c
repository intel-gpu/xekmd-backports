// SPDX-License-Identifier: MIT
/*
 * Copyright © 2021-2022 Intel Corporation
 * Copyright (C) 2021-2022 Red Hat
 */

#include "xe_ttm_sys_mgr.h"

#include <drm/drm_managed.h>

#include <drm/ttm/ttm_placement.h>
#include <drm/ttm/ttm_range_manager.h>
#include <drm/ttm/ttm_tt.h>

#include "xe_bo.h"

struct xe_ttm_sys_node {
	struct ttm_buffer_object *tbo;
	bool charged;
	struct ttm_range_mgr_node base;
};

static atomic64_t *to_charged_usage(struct ttm_resource_manager *man)
{
	return &container_of(man, struct xe_device, mem.sys_mgr)->mem.sys_mgr_charged;
}

static inline struct xe_ttm_sys_node *
to_xe_ttm_sys_node(struct ttm_resource *res)
{
	return container_of(res, struct xe_ttm_sys_node, base.base);
}

static int xe_ttm_sys_mgr_new(struct ttm_resource_manager *man,
			      struct ttm_buffer_object *tbo,
			      const struct ttm_place *place,
			      struct ttm_resource **res)
{
	struct xe_ttm_sys_node *node;
	int r;

	node = kzalloc_flex(*node, base.mm_nodes, 1);
	if (!node)
		return -ENOMEM;

	node->tbo = tbo;
	ttm_resource_init(tbo, place, &node->base.base);

	/*
	 * Imported dma-bufs are backed by the exporter (possibly peer VRAM),
	 * so don't charge them against the local system memory budget.
	 */
	if (tbo->type != ttm_bo_type_sg) {
		u64 size = node->base.base.size;
		u64 usage = atomic64_add_return(size, to_charged_usage(man));

		if (!(place->flags & TTM_PL_FLAG_TEMPORARY) &&
		    usage > (man->size << PAGE_SHIFT)) {
			atomic64_sub(size, to_charged_usage(man));
			r = -ENOSPC;
			goto err_fini;
		}
		node->charged = true;
	}

	node->base.mm_nodes[0].start = 0;
	node->base.mm_nodes[0].size = PFN_UP(node->base.base.size);
	node->base.base.start = XE_BO_INVALID_OFFSET;

	*res = &node->base.base;

	return 0;

err_fini:
	ttm_resource_fini(man, &node->base.base);
	kfree(node);
	return r;
}

static void xe_ttm_sys_mgr_del(struct ttm_resource_manager *man,
			       struct ttm_resource *res)
{
	struct xe_ttm_sys_node *node = to_xe_ttm_sys_node(res);

	if (node->charged)
		atomic64_sub(res->size, to_charged_usage(man));
	ttm_resource_fini(man, res);
	kfree(node);
}

static void xe_ttm_sys_mgr_debug(struct ttm_resource_manager *man,
				 struct drm_printer *printer)
{
	/*
	 * This function is called by debugfs entry and would require
	 * pm_runtime_{get,put} wrappers around any operation.
	 */
}

static const struct ttm_resource_manager_func xe_ttm_sys_mgr_func = {
	.alloc = xe_ttm_sys_mgr_new,
	.free = xe_ttm_sys_mgr_del,
	.debug = xe_ttm_sys_mgr_debug
};

static void xe_ttm_sys_mgr_fini(struct drm_device *drm, void *arg)
{
	struct xe_device *xe = (struct xe_device *)arg;
	struct ttm_resource_manager *man = &xe->mem.sys_mgr;
	int err;

	ttm_resource_manager_set_used(man, false);

	err = ttm_resource_manager_evict_all(&xe->ttm, man);
	if (err)
		return;

	ttm_resource_manager_cleanup(man);
	ttm_set_driver_manager(&xe->ttm, XE_PL_TT, NULL);
}

int xe_ttm_sys_mgr_init(struct xe_device *xe)
{
	struct ttm_resource_manager *man = &xe->mem.sys_mgr;
	struct sysinfo si;
	u64 gtt_size;

	si_meminfo(&si);
	/* Potentially restrict amount of TT memory here. */
	gtt_size = (u64)si.totalram * si.mem_unit;

	man->use_tt = true;
	man->func = &xe_ttm_sys_mgr_func;
	ttm_resource_manager_init(man, &xe->ttm, gtt_size >> PAGE_SHIFT);
	ttm_set_driver_manager(&xe->ttm, XE_PL_TT, man);
	ttm_resource_manager_set_used(man, true);
	return drmm_add_action_or_reset(&xe->drm, xe_ttm_sys_mgr_fini, xe);
}

/**
 * xe_ttm_sys_mgr_usage() - System memory charged against the TT budget
 * @xe: The xe device.
 *
 * Return: Bytes of system memory in use, excluding imported dma-bufs.
 */
u64 xe_ttm_sys_mgr_usage(struct xe_device *xe)
{
	return atomic64_read(&xe->mem.sys_mgr_charged);
}
