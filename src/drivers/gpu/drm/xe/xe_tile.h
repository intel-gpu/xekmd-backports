/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2023 Intel Corporation
 */

#ifndef _XE_TILE_H_
#define _XE_TILE_H_

#include "xe_hw_engine_types.h"
#include "xe_tile_types.h"

struct xe_device;
struct xe_pagemap;

int xe_tile_init_early(struct xe_tile *tile, struct xe_device *xe, u8 id);
int xe_tile_init_noalloc(struct xe_tile *tile);
int xe_tile_init(struct xe_tile *tile);

int xe_tile_alloc_vram(struct xe_tile *tile);

void xe_tile_migrate_wait(struct xe_tile *tile);

static inline bool xe_tile_is_root(struct xe_tile *tile)
{
	return tile->id == 0;
}

/**
 * xe_tile_pt_gt() - GT used to run a tile's page table update jobs
 * @tile: Pointer to the struct xe_tile.
 *
 * Page table updates, and the migration context they are submitted through,
 * normally run on the primary GT.  A device whose graphics IP is absent has
 * no primary GT, but its media GT can write page tables just as well.
 *
 * Return: The tile's primary GT, or its media GT if it has no primary GT.
 */
static inline struct xe_gt *xe_tile_pt_gt(struct xe_tile *tile)
{
	return tile->primary_gt ?: tile->media_gt;
}

/**
 * xe_tile_pt_class() - Engine class to run a tile's page table update jobs on
 * @tile: Pointer to the struct xe_tile.
 *
 * The engine class to pair with xe_tile_pt_gt(). The copy engine is the usual
 * choice, but it lives on the primary GT; when there is none, fall back to a
 * video decode engine on the media GT.
 *
 * Return: The engine class to create the tile's page table exec queue with.
 */
static inline enum xe_engine_class xe_tile_pt_class(struct xe_tile *tile)
{
	return tile->primary_gt ? XE_ENGINE_CLASS_COPY :
				  XE_ENGINE_CLASS_VIDEO_DECODE;
}

/**
 * xe_tile_to_vr() - Return the struct xe_vram_region pointer from a
 * struct xe_tile pointer
 * @tile: Pointer to the struct xe_tile.
 *
 * Return: Pointer to the struct xe_vram_region embedded in *@tile.
 */
static inline struct xe_vram_region *xe_tile_to_vr(struct xe_tile *tile)
{
	return tile->mem.vram;
}

#if IS_ENABLED(CPTCFG_DRM_XE_PAGEMAP)
struct drm_pagemap *xe_tile_local_pagemap(struct xe_tile *tile);
#else
static inline struct drm_pagemap *xe_tile_local_pagemap(struct xe_tile *tile)
{
	return NULL;
}
#endif
#endif
