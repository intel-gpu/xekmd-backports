/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2023 Intel Corporation
 */

#ifndef __XE_EUDEBUG_TYPES_H_
#define __XE_EUDEBUG_TYPES_H_

#include <linux/completion.h>
#include <linux/kfifo.h>
#include <linux/kref.h>
#include <linux/mutex.h>
#include <linux/rbtree.h>
#include <linux/rhashtable.h>
#include <linux/wait.h>
#include <linux/xarray.h>

#include <uapi/drm/xe_drm.h>

#include "xe_gt_debug.h"

struct xe_device;
struct task_struct;
struct xe_eudebug;
struct xe_eudebug_event;
struct xe_hw_engine;
struct workqueue_struct;
struct xe_exec_queue;
struct xe_lrc;

#define CONFIG_DRM_XE_DEBUGGER_EVENT_QUEUE_SIZE 64

/**
 * struct xe_eudebug_handle - eudebug resource handle
 */
struct xe_eudebug_handle {
	/** @key: key value in rhashtable <key:id> */
	u64 key;

	/** @id: opaque handle id for xarray <id:key> */
	int id;

	/** @rh_head: rhashtable head */
	struct rhash_head rh_head;
};

/**
 * struct xe_eudebug_resource - Resource map for one resource
 */
struct xe_eudebug_resource {
	/** @xa: xarrays for <id->key> */
	struct xarray xa;

	/** @rh rhashtable for <key->id> */
	struct rhashtable rh;
};

#define XE_EUDEBUG_RES_TYPE_CLIENT	0
#define XE_EUDEBUG_RES_TYPE_VM		1
#define XE_EUDEBUG_RES_TYPE_EXEC_QUEUE	2
#define XE_EUDEBUG_RES_TYPE_LRC		3
#define XE_EUDEBUG_RES_TYPE_METADATA	4
#define XE_EUDEBUG_RES_TYPE_COUNT	(XE_EUDEBUG_RES_TYPE_METADATA + 1)

/**
 * struct xe_eudebug_resources - eudebug resources for all types
 */
struct xe_eudebug_resources {
	/** @lock: guards access into rt */
	struct mutex lock;

	/** @rt: resource maps for all types */
	struct xe_eudebug_resource rt[XE_EUDEBUG_RES_TYPE_COUNT];
};

/**
 * struct xe_eudebug_eu_control_ops - interface for eu thread
 * state control backend
 */
struct xe_eudebug_eu_control_ops {
	/** @interrupt_all: interrupts workload active on given hwe */
	int (*interrupt_all)(struct xe_eudebug *e, struct xe_exec_queue *q,
			     struct xe_lrc *lrc);

	/** @resume: resumes threads reflected by bitmask active on given hwe */
	int (*resume)(struct xe_eudebug *e, struct xe_exec_queue *q,
		      struct xe_lrc *lrc, u8 *bitmap, unsigned int bitmap_size);

	/** @stopped: returns bitmap reflecting threads which signal attention */
	int (*stopped)(struct xe_eudebug *e, struct xe_exec_queue *q,
		       struct xe_lrc *lrc, u8 *bitmap, unsigned int bitmap_size);
};

/**
 * struct xe_eudebug - Top level struct for eudebug: the connection
 */
struct xe_eudebug {
	/** @ref: kref counter for this struct */
	struct kref ref;

	/** @rcu: rcu_head for rcu destruction */
	struct rcu_head rcu;

	/** @connection_link: our link into the xe_device:eudebug.list */
	struct list_head connection_link;

	struct {
		/** @status: connected = 1, disconnected = error */
#define XE_EUDEBUG_STATUS_CONNECTED 1
		int status;

		/** @lock: guards access to status */
		spinlock_t lock;
	} connection;

	/** @xe: the parent device we are serving */
	struct xe_device *xe;

	/** @target_task: the task that we are debugging */
	struct task_struct *target_task;

	/** @res: the resource maps we track for target_task */
	struct xe_eudebug_resources *res;

	/** @session: session number for this connection (for logs) */
	u64 session;

	/** @discovery: completion to wait for discovery */
	struct completion discovery;

	/** @discovery_work: worker to discover resources for target_task */
	struct work_struct discovery_work;

	/** eu_lock: guards operations on eus (eu thread control and attention) */
	struct mutex eu_lock;

	/** @events: kfifo queue of to-be-delivered events */
	struct {
		/** @lock: guards access to fifo */
		spinlock_t lock;

		/** @fifo: queue of events pending */
		DECLARE_KFIFO(fifo,
			      struct xe_eudebug_event *,
			      CONFIG_DRM_XE_DEBUGGER_EVENT_QUEUE_SIZE);

		/** @write_done: waitqueue for signalling write to fifo */
		wait_queue_head_t write_done;

		/** @read_done: waitqueue for signalling read from fifo */
		wait_queue_head_t read_done;

		/** @event_seqno: seqno counter to stamp events for fifo */
		atomic_long_t seqno;
	} events;

	/* user fences tracked by this debugger */
	struct {
		/** @lock: guards access to tree */
		spinlock_t lock;

		struct rb_root tree;
	} acks;

	/** @ops operations for eu_control */
	struct xe_eudebug_eu_control_ops *ops;

	/** @pf_lock: guards access to pagefaults list*/
	struct mutex pf_lock;
	/** @pagefaults: xe_eudebug_pagefault list for pagefault event queuing */
	struct list_head pagefaults;
	/**
	 * @pf_fence: fence on operations of eus (eu thread control and attention)
	 * when page faults are being handled, protected by @eu_lock.
	 */
	struct dma_fence __rcu *pf_fence;
};

/**
 * struct xe_eudebug_event - Internal base event struct for eudebug
 */
struct xe_eudebug_event {
	/** @len: length of this event, including payload */
	u32 len;

	/** @type: message type */
	u16 type;

	/** @flags: message flags */
	u16 flags;

	/** @seqno: sequence number for ordering */
	u64 seqno;

	/** @reserved: reserved field MBZ */
	u64 reserved;

	/** @data: payload bytes */
	u8 data[];
};

struct xe_eudebug_event_envelope {
	struct list_head link;
	struct xe_eudebug_event *event;
};

/**
 * struct xe_eudebug_event_open - Internal event for client open/close
 */
struct xe_eudebug_event_open {
	/** @base: base event */
	struct xe_eudebug_event base;

	/** @client_handle: opaque handle for client */
	u64 client_handle;
};

/**
 * struct xe_eudebug_event_vm - Internal event for vm open/close
 */
struct xe_eudebug_event_vm {
	/** @base: base event */
	struct xe_eudebug_event base;

	/** @client_handle: client containing the vm open/close */
	u64 client_handle;

	/** @vm_handle: vm handle it's open/close */
	u64 vm_handle;
};

/**
 * struct xe_eudebug_event_exec_queue - Internal event for
 * exec_queue create/destroy
 */
struct xe_eudebug_event_exec_queue {
	/** @base: base event */
	struct xe_eudebug_event base;

	/** @client_handle: client for the engine create/destroy */
	u64 client_handle;

	/** @vm_handle: vm handle for the engine create/destroy */
	u64 vm_handle;

	/** @exec_queue_handle: engine handle */
	u64 exec_queue_handle;

	/** @engine_handle: engine class */
	u32 engine_class;

	/** @width: submission width (number BB per exec) for this exec queue */
	u32 width;

	/** @lrc_handles: handles for each logical ring context created with this exec queue */
	u64 lrc_handle[] __counted_by(width);
};

struct xe_eudebug_event_exec_queue_placements {
	/** @base: base event */
	struct xe_eudebug_event base;

	/** @client_handle: client for the engine create/destroy */
	u64 client_handle;

	/** @vm_handle: vm handle for the engine create/destroy */
	u64 vm_handle;

	/** @exec_queue_handle: engine handle */
	u64 exec_queue_handle;

	/** @engine_handle: engine class */
	u64 lrc_handle;

	/** @num_placements: all possible placements for given lrc */
	u32 num_placements;

	/** @pad: padding */
	u32 pad;

	/** @instances: num_placements sized array containing drm_xe_engine_class_instance*/
	u64 instances[]; __counted_by(num_placements);
};

/**
 * struct xe_eudebug_event_eu_attention - Internal event for EU attention
 */
struct xe_eudebug_event_eu_attention {
	/** @base: base event */
	struct xe_eudebug_event base;

	/** @client_handle: client for the attention */
	u64 client_handle;

	/** @exec_queue_handle: handle of exec_queue which raised attention */
	u64 exec_queue_handle;

	/** @lrc_handle: lrc handle of the workload which raised attention */
	u64 lrc_handle;

	/** @flags: eu attention event flags, currently MBZ */
	u32 flags;

	/** @bitmask_size: size of the bitmask, specific to device */
	u32 bitmask_size;

	/**
	 * @bitmask: reflects threads currently signalling attention,
	 * starting from natural hardware order of DSS=0, eu=0
	 */
	u8 bitmask[] __counted_by(bitmask_size);
};

/**
 * struct xe_eudebug_event_vm_bind - Internal event for vm bind/unbind operation
 */
struct xe_eudebug_event_vm_bind {
	/** @base: base event */
	struct xe_eudebug_event base;

	u64 client_handle;
	u64 vm_handle;

	u32 flags;
	u32 num_binds;
};

struct xe_eudebug_event_vm_bind_op {
	/** @base: base event */
	struct xe_eudebug_event base;
	u64 vm_bind_ref_seqno;
	u64 num_extensions;

	u64 addr; /* Zero for unmap all ? */
	u64 range; /* Zero for unmap all ? */
};

struct xe_eudebug_event_vm_bind_ufence {
	struct xe_eudebug_event base;
	u64 vm_bind_ref_seqno;
};

struct xe_eudebug_event_metadata {
	struct xe_eudebug_event base;

	/** @client_handle: client for the attention */
	u64 client_handle;

	/** @metadata_handle: debug metadata handle it's created/destroyed */
	u64 metadata_handle;

	/* @type: metadata type, refer to xe_drm.h for options */
	u64 type;

	/* @len: size of metadata paylad */
	u64 len;
};

struct xe_eudebug_event_vm_bind_op_metadata {
	struct xe_eudebug_event base;
	u64 vm_bind_op_ref_seqno;

	u64 metadata_handle;
	u64 metadata_cookie;
};

/**
 * struct xe_eudebug_event_pagefault - Internal event for EU Pagefault
 */
struct xe_eudebug_event_pagefault {
	/** @base: base event */
	struct xe_eudebug_event base;

	/** @client_handle: client for the Pagefault */
	u64 client_handle;

	/** @exec_queue_handle: handle of exec_queue which raised Pagefault */
	u64 exec_queue_handle;

	/** @lrc_handle: lrc handle of the workload which raised Pagefault */
	u64 lrc_handle;

	/** @flags: eu Pagefault event flags, currently MBZ */
	u32 flags;

	/**
	 * @bitmask_size: sum of size before/after/resolved att bits.
	 * It has three times the size of xe_eudebug_event_eu_attention.bitmask_size.
	 */
	u32 bitmask_size;

	/** @pagefault_address: The ppgtt address where the Pagefault occurred */
	u64 pagefault_address;

	/**
	 * @bitmask: Bitmask of thread attentions starting from natural,
	 * hardware order of DSS=0, eu=0, 8 attention bits per eu.
	 * The order of the bitmask array is before, after, resolved.
	 */
	u8 bitmask[];
};

/**
 * struct xe_eudebug_pagefault - eudebug structure for queuing pagefault
 */
struct xe_eudebug_pagefault {
	/** @list: link into the xe_eudebug.pagefaults */
	struct list_head list;
	/** @q: exec_queue which raised pagefault */
	struct xe_exec_queue *q;
	/** @lrc_idx: lrc index of the workload which raised pagefault */
	int lrc_idx;

	/* pagefault raw partial data passed from guc*/
	struct {
		/** @addr: ppgtt address where the pagefault occurred */
		u64 addr;
		int type;
		int level;
		int access;
	} fault;

	struct {
		/** @before: state of attention bits before page fault WA processing*/
		struct xe_eu_attentions before;
		/**
		 * @after: status of attention bits during page fault WA processing.
		 * It includes eu threads where attention bits are turned on for
		 * reasons other than page fault WA (breakpoint, interrupt, etc.).
		 */
		struct xe_eu_attentions after;
		/**
		 * @resolved: state of the attention bits after page fault WA.
		 * It includes the eu thread that caused the page fault.
		 * To determine the eu thread that caused the page fault,
		 * do XOR attentions.after and attentions.resolved.
		 */
		struct xe_eu_attentions resolved;
	} attentions;

	/**
	 * @deferred_resolved: to update attentions.resolved again when attention
	 * bits are ready if the eu thread fails to turn on attention bits within
	 * a certain time after page fault WA processing.
	 */
	bool deferred_resolved;
};

#endif
