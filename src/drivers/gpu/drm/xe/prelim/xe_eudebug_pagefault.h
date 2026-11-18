/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2023-2025 Intel Corporation
 */

#ifndef PRELIM__XE_EUDEBUG_PAGEFAULT_H_
#define PRELIM__XE_EUDEBUG_PAGEFAULT_H_

#include <linux/types.h>

struct xe_device;
struct xe_eudebug;
struct xe_gt;
struct xe_pagefault;
struct xe_eudebug_pagefault;
struct xe_vm;
struct xe_vma;
struct xe_file;

#if IS_ENABLED(CPTCFG_PRELIM_DRM_XE_EUDEBUG)
void prelim_xe_eudebug_pagefault_fini(struct xe_eudebug *d);
int prelim_xe_eudebug_handle_pagefaults(struct xe_gt *gt);

void prelim_xe_eudebug_pagefault_gt_init(struct xe_gt *gt);

int prelim_xe_eudebug_pagefault_start(struct xe_vm *vm, struct xe_vma *vma,
			       struct xe_pagefault *pf);
struct xe_vma *prelim_xe_eudebug_create_vma(struct xe_vm *vm, struct xe_pagefault *pf);
void prelim_xe_eudebug_pagefault_end(void *private, u32 asid, int err);
/*
 * The (struct xe_pagefault *)->producer.private is a pointer which, for now,
 * stores the pointer guc.
 * EU Debug intercepts this pointer to store struct xe_eudebug_pagefault.
 * Original pointer can be obtained via eudebug function below called with
 * mentioned producer's private field.
 */
#define PRELIM_XE_EUDEBUG_PAGEFAULT_PRIVATE_EUDEBUG	0x1
void prelim_xe_eudebug_pagefault_set_private(struct xe_pagefault *pf,
				      struct xe_vm *vm);
void *prelim_xe_eudebug_pagefault_get_private(void *private);

void prelim_xe_eudebug_pagefault_signal(struct xe_eudebug *d);

bool prelim_xe_eudebug_pagefault_creatable(struct xe_gt *gt, struct xe_vm *vm);

void prelim_xe_eudebug_pagefault_reset(struct xe_device *xe, struct xe_gt *gt);

#else
#include <linux/errno.h>
#include <linux/err.h>

static inline void prelim_xe_eudebug_pagefault_fini(struct xe_eudebug *d)
{
}

static inline int prelim_xe_eudebug_handle_pagefaults(struct xe_gt *gt)
{
	return -EOPNOTSUPP;
}

static inline void prelim_xe_eudebug_pagefault_gt_init(struct xe_gt *gt)
{
}

static inline int
prelim_xe_eudebug_pagefault_start(struct xe_vm *vm, struct xe_vma *vma, struct xe_pagefault *pf)
{
	return -EOPNOTSUPP;
}

static inline void prelim_xe_eudebug_pagefault_end(void *private, u32 asid, int err)
{
}

static inline struct xe_vma *prelim_xe_eudebug_create_vma(struct xe_vm *vm,
						   struct xe_pagefault *pf)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static inline void prelim_xe_eudebug_pagefault_set_private(struct xe_pagefault *pf,
						    struct xe_vm *vm)
{
}

static inline void *prelim_xe_eudebug_pagefault_get_private(void *private)
{
	return private;
}

static inline void prelim_xe_eudebug_pagefault_signal(struct xe_eudebug *d)
{
}

static inline bool prelim_xe_eudebug_pagefault_creatable(struct xe_gt *gt,
						  struct xe_vm *vm)
{
	return false;
}

static inline void prelim_xe_eudebug_pagefault_reset(struct xe_device *xe,
					      struct xe_gt *gt)
{
}

#endif

#endif /* PRELIM__XE_EUDEBUG_PAGEFAULT_H_ */
