/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2022 Intel Corporation
 */

#ifndef _XE_SYNC_TYPES_H_
#define _XE_SYNC_TYPES_H_

#include <linux/dma-fence-array.h>
#include <linux/kref.h>
#include <linux/spinlock.h>
#include <linux/types.h>

struct xe_user_fence {
	struct xe_device *xe;
	struct kref refcount;
	struct dma_fence_cb cb;
	struct work_struct worker;
	struct mm_struct *mm;
	u64 __user *addr;
	u64 value;
	int signalled;

#if IS_ENABLED(CPTCFG_PRELIM_DRM_XE_EUDEBUG)
	struct {
		spinlock_t lock;
		struct xe_eudebug *debugger;
		u64 bind_ref_seqno;
		u64 signalled_seqno;
		struct work_struct worker;
	} eudebug;
#endif
};

struct xe_sync_entry {
	struct drm_syncobj *syncobj;
	struct dma_fence *fence;
	struct dma_fence_chain *chain_fence;
	struct xe_user_fence *ufence;
	u64 addr;
	u64 timeline_value;
	u32 type;
	u32 flags;
};

#endif
