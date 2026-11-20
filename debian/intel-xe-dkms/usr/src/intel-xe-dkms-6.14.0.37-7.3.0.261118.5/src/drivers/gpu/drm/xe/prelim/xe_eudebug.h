/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2023-2025 Intel Corporation
 */

#ifndef _XE_EUDEBUG_H_
#define _XE_EUDEBUG_H_

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
struct xe_eudebug;
struct xe_eudebug_pagefault;
struct xe_lrc;

#if IS_ENABLED(CPTCFG_PRELIM_DRM_XE_EUDEBUG)
#define XE_EUDEBUG_DBG_STR "eudbg: %lld:%lu:%s (%d/%d) -> (%d/%d): "
#define XE_EUDEBUG_DBG_ARGS(d) (d)->session, \
		atomic_long_read(&(d)->events.seqno), \
		READ_ONCE(d->connection.status) <= 0 ? "disconnected" : "", \
		current->pid, \
		task_tgid_nr(current), \
		(d)->target_task->pid, \
		task_tgid_nr((d)->target_task)

#define eu_err(d, fmt, ...) drm_err(&(d)->xe->drm, XE_EUDEBUG_DBG_STR # fmt, \
				    XE_EUDEBUG_DBG_ARGS(d), ##__VA_ARGS__)
#define eu_warn(d, fmt, ...) drm_warn(&(d)->xe->drm, XE_EUDEBUG_DBG_STR # fmt, \
				      XE_EUDEBUG_DBG_ARGS(d), ##__VA_ARGS__)
#define eu_dbg(d, fmt, ...) drm_dbg(&(d)->xe->drm, XE_EUDEBUG_DBG_STR # fmt, \
				    XE_EUDEBUG_DBG_ARGS(d), ##__VA_ARGS__)

void prelim_xe_eudebug_disconnect(struct xe_eudebug *d,
			   const int err);
int prelim_xe_eudebug_connect_ioctl(struct drm_device *dev,
			     void *data,
			     struct drm_file *file);

void prelim_xe_eudebug_init(struct xe_device *xe);

void prelim_xe_eudebug_file_open(struct xe_file *xef);
void prelim_xe_eudebug_file_close(struct xe_file *xef);

void prelim_xe_eudebug_vm_create(struct xe_file *xef, struct xe_vm *vm);
void prelim_xe_eudebug_vm_destroy(struct xe_file *xef, struct xe_vm *vm);

bool prelim_xe_eudebug_detached(struct xe_eudebug *d);

int prelim_xe_eudebug_enable(struct xe_device *xe, bool enable);

bool prelim_xe_eudebug_is_enabled(struct xe_device *xe);

struct xe_eudebug *prelim_xe_eudebug_get_nolock(struct xe_file *xef);
struct xe_eudebug *prelim_xe_eudebug_get_nolock_with_discovery(struct xe_file *xef);

struct xe_vm *prelim_xe_eudebug_vm_get(struct xe_eudebug *d, u32 vm_id);

void prelim_xe_eudebug_exec_queue_create(struct xe_file *xef, struct xe_exec_queue *q);
void prelim_xe_eudebug_exec_queue_destroy(struct xe_file *xef, struct xe_exec_queue *q);

void prelim_xe_eudebug_vm_init(struct xe_vm *vm);
void prelim_xe_eudebug_vm_bind_start(struct xe_vm *vm);
void prelim_xe_eudebug_vm_bind_op_add(struct xe_vm *vm, u32 op, u64 addr, u64 range,
			       struct drm_gpuva_ops *ops);
void prelim_xe_eudebug_vm_bind_end(struct xe_vm *vm, struct xe_user_fence *ufence, int err);

int prelim_xe_eudebug_vm_bind_ufence(struct xe_user_fence *ufence);

struct xe_eudebug *prelim_xe_eudebug_get(struct xe_file *xef);
struct xe_eudebug *prelim_xe_eudebug_instance_get(struct xe_eudebug *d);
void prelim_xe_eudebug_put(struct xe_eudebug *d);

void prelim_xe_eudebug_debug_metadata_create(struct xe_file *xef, struct prelim_xe_debug_metadata *m);
void prelim_xe_eudebug_debug_metadata_destroy(struct xe_file *xef, struct prelim_xe_debug_metadata *m);

int prelim_xe_eudebug_send_pagefault_event(struct xe_eudebug *d,
				    struct xe_eudebug_pagefault *pf);

void prelim_xe_eudebug_attention_poll_stop(struct xe_device *xe);
void prelim_xe_eudebug_attention_poll_start(struct xe_device *xe);

struct xe_exec_queue *xe_gt_runalone_active_queue_get(struct xe_gt *gt, int *lrc_idx);
struct xe_exec_queue *xe_gt_runalone_active_queue_get_lockless(struct xe_gt *gt, int *lrc_idx);

int prelim_xe_eudebug_sync_host(struct xe_exec_queue *q, struct xe_lrc *lrc);

bool prelim_xe_eudebug_client_tracked(struct xe_file *xef);

#else

static inline int prelim_xe_eudebug_connect_ioctl(struct drm_device *dev,
					   void *data,
					   struct drm_file *file) { return 0; }

static inline void prelim_xe_eudebug_init(struct xe_device *xe) { }

static inline void prelim_xe_eudebug_file_open(struct xe_file *xef) { }
static inline void prelim_xe_eudebug_file_close(struct xe_file *xef) { }

static inline void prelim_xe_eudebug_vm_create(struct xe_file *xef, struct xe_vm *vm) { }
static inline void prelim_xe_eudebug_vm_destroy(struct xe_file *xef, struct xe_vm *vm) { }

static inline void prelim_xe_eudebug_exec_queue_create(struct xe_file *xef, struct xe_exec_queue *q) { }
static inline void prelim_xe_eudebug_exec_queue_destroy(struct xe_file *xef, struct xe_exec_queue *q) { }

static inline void prelim_xe_eudebug_vm_init(struct xe_vm *vm) { }
static inline void prelim_xe_eudebug_vm_bind_start(struct xe_vm *vm) { }
static inline void prelim_xe_eudebug_vm_bind_op_add(struct xe_vm *vm, u32 op, u64 addr, u64 range,
					     struct drm_gpuva_ops *ops) { }
static inline void prelim_xe_eudebug_vm_bind_end(struct xe_vm *vm, struct xe_user_fence *ufence, int err) { }

static inline int prelim_xe_eudebug_vm_bind_ufence(struct xe_user_fence *ufence) { return 0; }

static inline struct xe_eudebug *prelim_xe_eudebug_get(struct xe_file *xef) { return NULL; }
static inline void prelim_xe_eudebug_put(struct xe_eudebug *d) { }

static inline void prelim_xe_eudebug_debug_metadata_create(struct xe_file *xef,
						    struct prelim_xe_debug_metadata *m)
{
}

static inline void prelim_xe_eudebug_debug_metadata_destroy(struct xe_file *xef,
						     struct prelim_xe_debug_metadata *m)
{
}

static inline bool prelim_xe_eudebug_is_enabled(struct xe_device *xe)
{
	return false;
}

static inline int prelim_xe_eudebug_sync_host(struct xe_exec_queue *q, struct xe_lrc *lrc) { return 0; }

static inline bool prelim_xe_eudebug_client_tracked(struct xe_file *xef) { return false; }

#endif /* CPTCFG_PRELIM_DRM_XE_EUDEBUG */

#endif /* _XE_EUDEBUG_H_ */
