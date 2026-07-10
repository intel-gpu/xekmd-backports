/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Compatibility header for gpu_buddy to drm_buddy mapping
 * Maps gpu_buddy API to drm_buddy based on kernel availability
 */

#ifndef _BACKPORT_LINUX_GPU_BUDDY_H_
#define _BACKPORT_LINUX_GPU_BUDDY_H_

#if defined(BPM_GPU_BUDDY_H_AVAILABLE) || defined(CPTCFG_BUILD_XE_DRM_BUDDY)
#include_next <linux/gpu_buddy.h>

#else
/* Kernel doesn't have gpu_buddy.h, use drm_buddy instead */
#include_next <drm/drm_buddy.h>

/* Type mappings */
#define gpu_buddy drm_buddy
#define gpu_buddy_block drm_buddy_block
#define gpu_buddy_mm drm_buddy_mm
#define gpu_buddy_addr_state drm_buddy_addr_state

/* Flag mappings */
#define GPU_BUDDY_TOPDOWN_ALLOCATION  DRM_BUDDY_TOPDOWN_ALLOCATION
#define GPU_BUDDY_RANGE_ALLOCATION DRM_BUDDY_RANGE_ALLOCATION
#ifdef BPM_DRM_BUDDY_CONTIGUOUS_ALLOCATION_PRESENT
#define GPU_BUDDY_CONTIGUOUS_ALLOCATION  DRM_BUDDY_CONTIGUOUS_ALLOCATION
#endif
/* Function mappings */
#define gpu_buddy_init drm_buddy_init
#define gpu_buddy_fini drm_buddy_fini
#define gpu_buddy_alloc_blocks drm_buddy_alloc_blocks
#define gpu_buddy_free_list drm_buddy_free_list
#define gpu_buddy_alloc drm_buddy_alloc
#define gpu_buddy_free drm_buddy_free
#define gpu_buddy_block_offset drm_buddy_block_offset
#define gpu_buddy_block_size drm_buddy_block_size
#define gpu_buddy_print_tree drm_buddy_print_tree
#define gpu_buddy_block_trim drm_buddy_block_trim

#endif /* BPM_GPU_BUDDY_H_AVAILABLE || CPTCFG_BUILD_XE_DRM_BUDDY */

#endif /* _BACKPORT_LINUX_GPU_BUDDY_H_ */
