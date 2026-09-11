/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _BACKPORT_LINUX_GPU_BUDDY_H_
#define _BACKPORT_LINUX_GPU_BUDDY_H_

#if defined(HAVE_LINUX_GPU_BUDDY_H_AVAILABLE) || defined(CPTCFG_BUILD_XE_DRM_BUDDY)
#include_next <linux/gpu_buddy.h>
#else
#include <drm/drm_buddy.h>
#include <linux/log2.h>

/* Type mappings */
#define gpu_buddy drm_buddy
#define gpu_buddy_block drm_buddy_block
#define gpu_buddy_mm drm_buddy_mm
#define gpu_buddy_addr_state drm_buddy_addr_state

/* Flag mappings */
#define GPU_BUDDY_TOPDOWN_ALLOCATION  DRM_BUDDY_TOPDOWN_ALLOCATION
#define GPU_BUDDY_RANGE_ALLOCATION DRM_BUDDY_RANGE_ALLOCATION
#ifdef BPM_DRM_BUDDY_CONTIGUOUS_ALLOCATION_NOT_PRESENT
#define GPU_BUDDY_CONTIGUOUS_ALLOCATION  BIT(2)
#define DRM_BUDDY_CONTIGUOUS_ALLOCATION  GPU_BUDDY_CONTIGUOUS_ALLOCATION
#else
#define GPU_BUDDY_CONTIGUOUS_ALLOCATION  DRM_BUDDY_CONTIGUOUS_ALLOCATION
#endif

/* Function mappings */
#define gpu_buddy_init drm_buddy_init
#define gpu_buddy_fini drm_buddy_fini
#define gpu_buddy_free_list drm_buddy_free_list
#define gpu_buddy_alloc drm_buddy_alloc
#define gpu_buddy_free drm_buddy_free
#define gpu_buddy_block_offset drm_buddy_block_offset
#define gpu_buddy_block_size drm_buddy_block_size
#define gpu_buddy_print_tree drm_buddy_print_tree
#define gpu_buddy_block_trim drm_buddy_block_trim
#define gpu_buddy_driver_set_lock(mm, lock) do { (void)(mm); (void)(lock); } while (0)
struct drm_buddy_block *
backport_gpu_buddy_allocated_addr_to_block(struct drm_buddy *mm, u64 addr);
#define gpu_buddy_allocated_addr_to_block backport_gpu_buddy_allocated_addr_to_block

#ifdef BPM_DRM_BUDDY_CONTIGUOUS_ALLOCATION_NOT_PRESENT
static inline int backport_gpu_buddy_alloc_blocks(struct drm_buddy *mm,
						  u64 start, u64 end, u64 size,
						  u64 min_page_size,
						  struct list_head *blocks,
						  unsigned long flags)
{
	int err;

	if (flags & DRM_BUDDY_CONTIGUOUS_ALLOCATION) {
		u64 orig_size = size;
		u64 alloc_size = roundup_pow_of_two(size);
		u64 alloc_min_page = alloc_size;
		unsigned long alloc_flags = flags & ~DRM_BUDDY_CONTIGUOUS_ALLOCATION;

		if (start + alloc_size > end)
			end = max_t(u64, start + alloc_size, end);

		err = drm_buddy_alloc_blocks(mm, start, end, alloc_size,
					     alloc_min_page, blocks, alloc_flags);
		if (err)
			return err;

		if (orig_size < alloc_size)
			gpu_buddy_block_trim(mm, NULL, orig_size, blocks);

		return 0;
	}

	return drm_buddy_alloc_blocks(mm, start, end, size, min_page_size, blocks, flags);
}
#define gpu_buddy_alloc_blocks backport_gpu_buddy_alloc_blocks
#else
#define gpu_buddy_alloc_blocks drm_buddy_alloc_blocks
#endif

#endif /* HAVE_LINUX_GPU_BUDDY_H_AVAILABLE || CPTCFG_BUILD_XE_DRM_BUDDY */

#endif /* _BACKPORT_LINUX_GPU_BUDDY_H_ */
