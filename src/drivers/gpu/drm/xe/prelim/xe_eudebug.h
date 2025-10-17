/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2023 Intel Corporation
 */

#ifndef _XE_EUDEBUG_H_

#include <linux/types.h>

struct drm_device;
struct drm_file;
struct xe_device;
struct xe_file;
struct xe_gt;
struct xe_vm;
struct xe_vma;
struct xe_exec_queue;
struct xe_hw_engine;
struct xe_user_fence;
struct prelim_xe_debug_metadata;
struct drm_gpuva_ops;
struct xe_eudebug_pagefault;

#if IS_ENABLED(CPTCFG_PRELIM_DRM_XE_EUDEBUG)

int prelim_xe_eudebug_connect_ioctl(struct drm_device *dev,
			     void *data,
			     struct drm_file *file);

void prelim_xe_eudebug_init(struct xe_device *xe);
void prelim_xe_eudebug_fini(struct xe_device *xe);

void prelim_xe_eudebug_file_open(struct xe_file *xef);
void prelim_xe_eudebug_file_close(struct xe_file *xef);

void prelim_xe_eudebug_vm_create(struct xe_file *xef, struct xe_vm *vm);
void prelim_xe_eudebug_vm_destroy(struct xe_file *xef, struct xe_vm *vm);

void prelim_xe_eudebug_exec_queue_create(struct xe_file *xef, struct xe_exec_queue *q);
void prelim_xe_eudebug_exec_queue_destroy(struct xe_file *xef, struct xe_exec_queue *q);

void prelim_xe_eudebug_vm_init(struct xe_vm *vm);
void prelim_xe_eudebug_vm_bind_start(struct xe_vm *vm);
void prelim_xe_eudebug_vm_bind_op_add(struct xe_vm *vm, u32 op, u64 addr, u64 range,
			       struct drm_gpuva_ops *ops);
void prelim_xe_eudebug_vm_bind_end(struct xe_vm *vm, bool has_ufence, int err);

int prelim_xe_eudebug_vm_bind_ufence(struct xe_user_fence *ufence);
void prelim_xe_eudebug_ufence_init(struct xe_user_fence *ufence, struct xe_file *xef, struct xe_vm *vm);
void prelim_xe_eudebug_ufence_fini(struct xe_user_fence *ufence);

struct xe_eudebug *prelim_xe_eudebug_get(struct xe_file *xef);
void prelim_xe_eudebug_put(struct xe_eudebug *d);

void prelim_xe_eudebug_debug_metadata_create(struct xe_file *xef, struct prelim_xe_debug_metadata *m);
void prelim_xe_eudebug_debug_metadata_destroy(struct xe_file *xef, struct prelim_xe_debug_metadata *m);

struct xe_eudebug_pagefault *prelim_xe_eudebug_pagefault_create(struct xe_gt *gt, struct xe_vm *vm,
							 u64 page_addr, u8 fault_type,
							 u8 fault_level, u8 access_type);
void prelim_xe_eudebug_pagefault_process(struct xe_gt *gt, struct xe_eudebug_pagefault *pf);
void prelim_xe_eudebug_pagefault_destroy(struct xe_gt *gt, struct xe_vm *vm,
				  struct xe_eudebug_pagefault *pf, bool send_event);

#else

static inline int prelim_xe_eudebug_connect_ioctl(struct drm_device *dev,
					   void *data,
					   struct drm_file *file) { return 0; }

static inline void prelim_xe_eudebug_init(struct xe_device *xe) { }
static inline void prelim_xe_eudebug_fini(struct xe_device *xe) { }

static inline void prelim_xe_eudebug_file_open(struct xe_file *xef) { }
static inline void prelim_xe_eudebug_file_close(struct xe_file *xef) { }

static inline void prelim_xe_eudebug_vm_create(struct xe_file *xef, struct xe_vm *vm) { }
static inline void prelim_xe_eudebug_vm_destroy(struct xe_file *xef, struct xe_vm *vm) { }

static inline void prelim_xe_eudebug_exec_queue_create(struct xe_file *xef, struct xe_exec_queue *q) { }
static inline void prelim_xe_eudebug_exec_queue_destroy(struct xe_file *xef, struct xe_exec_queue *q) { }

static inline void prelim_xe_eudebug_vm_init(struct xe_vm *vm) { }
static inline void prelim_xe_eudebug_vm_bind_start(struct xe_vm *vm) { }
static inline void prelim_xe_eudebug_vm_bind_op_add(struct xe_vm *vm, u32 op, u64 addr, u64 range, struct drm_gpuva_ops *ops) { }
static inline void prelim_xe_eudebug_vm_bind_end(struct xe_vm *vm, bool has_ufence, int err) { }

static inline int prelim_xe_eudebug_vm_bind_ufence(struct xe_user_fence *ufence) { return 0; }
static inline void prelim_xe_eudebug_ufence_init(struct xe_user_fence *ufence, struct xe_file *xef, struct xe_vm *vm) { }
static inline void prelim_xe_eudebug_ufence_fini(struct xe_user_fence *ufence) { }

static inline struct xe_eudebug *prelim_xe_eudebug_get(struct xe_file *xef) { return NULL; }
static inline void prelim_xe_eudebug_put(struct xe_eudebug *d) { }

static inline void prelim_xe_eudebug_debug_metadata_create(struct xe_file *xef, struct xe_debug_metadata *m) { }
static inline void prelim_xe_eudebug_debug_metadata_destroy(struct xe_file *xef, struct xe_debug_metadata *m) { }

static inline struct xe_eudebug_pagefault *prelim_xe_eudebug_pagefault_create(struct xe_gt *gt, struct xe_vm *vm,
								       u64 page_addr, u8 fault_type,
								       u8 fault_level, u8 access_type) { return NULL; }
static inline void prelim_xe_eudebug_pagefault_process(struct xe_gt *gt, struct xe_eudebug_pagefault *pf) { }
static inline void prelim_xe_eudebug_pagefault_destroy(struct xe_gt *gt, struct xe_vm *vm, struct xe_eudebug_pagefault *pf, bool send_event) { }

#endif /* CPTCFG_PRELIM_DRM_XE_EUDEBUG */

#endif
