// SPDX-License-Identifier: MIT
/*
 * Copyright © 2023 Intel Corporation
 */
#include <linux/circ_buf.h>

#include <linux/delay.h>
#include "regs/xe_gt_regs.h"
#include "xe_device.h"
#include "prelim/xe_eudebug.h"
#include "xe_exec_queue.h"
#include "xe_force_wake.h"
#include "xe_gt.h"
#include "prelim/xe_gt_debug.h"
#include "xe_gt_mcr.h"
#include "xe_gt_topology.h"
#include "xe_gt_types.h"
#include "xe_guc.h"
#include "xe_guc_exec_queue_types.h"
#include "xe_pm.h"
#include "xe_macros.h"

unsigned int prelim_xe_gt_eu_att_regs(struct xe_gt *gt)
{
	return (GRAPHICS_VERx100(gt_to_xe(gt)) >= 3000) ? 2u : 1u;
}

int prelim_xe_gt_foreach_dss_group_instance(struct xe_gt *gt,
				     int (*fn)(struct xe_gt *gt,
					       void *data,
					       u16 group,
					       u16 instance,
					       bool present),
				     void *data)
{
	const enum xe_force_wake_domains fw_domains = XE_FW_GT;
	xe_dss_mask_t dss_mask;
	unsigned int dss, fw_ref;
	u16 group, instance;
	int ret = 0;

	fw_ref = xe_force_wake_get(gt_to_fw(gt), fw_domains);
	if (!fw_ref)
		return -ETIMEDOUT;

	bitmap_or(dss_mask, gt->fuse_topo.g_dss_mask, gt->fuse_topo.c_dss_mask,
		  XE_MAX_DSS_FUSE_BITS);

	/*
	 * Note: This removes terminating zeros when last dss is fused out!
	 * In order bitmask to be exactly the same as on with i915 we would
	 * need to figure out max dss for given platform, most probably by
	 * querying hwconfig
	 */

	for (dss = 0;
	     dss <= find_last_bit(dss_mask, XE_MAX_DSS_FUSE_BITS);
	     dss++) {
		xe_gt_mcr_get_dss_steering(gt, dss, &group, &instance);

		ret = fn(gt, data, group, instance, test_bit(dss, dss_mask));
		if (ret)
			break;
	}

	xe_force_wake_put(gt_to_fw(gt), fw_ref);

	return ret;
}

static int read_first_attention_mcr(struct xe_gt *gt, void *data,
				    u16 group, u16 instance, bool present)
{
	unsigned int reg, row;

	if (!present)
		return 0;

	for (reg = 0; reg < prelim_xe_gt_eu_att_regs(gt); reg++) {
		for (row = 0; row < PRELIM_XE_GT_EU_ATT_ROWS; row++) {
			u32 val;

			val = xe_gt_mcr_unicast_read(gt, EU_ATT(reg, row), group, instance);

			if (val)
				return 1;
		}
	}

	return 0;
}

#define MAX_EUS_PER_ROW 4u
#define MAX_THREADS 8u

/**
 * prelim_xe_gt_eu_attention_bitmap_size - query size of the attention bitmask
 *
 * @gt: pointer to struct xe_gt
 *
 * Return: size in bytes.
 */
int prelim_xe_gt_eu_attention_bitmap_size(struct xe_gt *gt)
{
	xe_dss_mask_t dss_mask;

	if (xe_device_eudebug_uses_guc(gt_to_xe(gt)))
		return 0;

	bitmap_or(dss_mask, gt->fuse_topo.c_dss_mask,
		  gt->fuse_topo.g_dss_mask, XE_MAX_DSS_FUSE_BITS);

	return (find_last_bit(dss_mask, XE_MAX_DSS_FUSE_BITS) + 1) *
		PRELIM_XE_GT_EU_ATT_ROWS * prelim_xe_gt_eu_att_regs(gt) * MAX_THREADS *
		MAX_EUS_PER_ROW / 8;
}

struct attn_read_iter {
	struct xe_gt *gt;
	unsigned int i;
	unsigned int size;
	u8 *bits;
};

static int read_eu_attentions_mcr(struct xe_gt *gt, void *data,
				  u16 group, u16 instance, bool present)
{
	struct attn_read_iter * const iter = data;
	unsigned int reg, row;

	for (reg = 0; reg < prelim_xe_gt_eu_att_regs(gt); reg++) {
		for (row = 0; row < PRELIM_XE_GT_EU_ATT_ROWS; row++) {
			u32 val;

			if (iter->i >= iter->size)
				return 0;

			XE_WARN_ON(iter->i + sizeof(val) > prelim_xe_gt_eu_attention_bitmap_size(gt));

			if (present)
				val = xe_gt_mcr_unicast_read(gt, EU_ATT(reg, row), group, instance);
			else
				val = 0;

			memcpy(&iter->bits[iter->i], &val, sizeof(val));
			iter->i += sizeof(val);
		}
	}

	return 0;
}

/**
 * prelim_xe_gt_eu_attention_bitmap - query host attention
 *
 * @gt: pointer to struct xe_gt
 *
 * Return: 0 on success, negative otherwise.
 */
int prelim_xe_gt_eu_attention_bitmap(struct xe_gt *gt, u8 *bits,
			      unsigned int bitmap_size)
{
	struct attn_read_iter iter = {
		.gt = gt,
		.i = 0,
		.size = bitmap_size,
		.bits = bits
	};

	return prelim_xe_gt_foreach_dss_group_instance(gt, read_eu_attentions_mcr, &iter);
}

/**
 * prelim_xe_gt_eu_threads_needing_attention - Query host attention
 *
 * @gt: pointer to struct xe_gt
 *
 * Return: 1 if threads waiting host attention, 0 otherwise.
 */
int prelim_xe_gt_eu_threads_needing_attention(struct xe_gt *gt)
{
	int err;

	err = prelim_xe_gt_foreach_dss_group_instance(gt, read_first_attention_mcr, NULL);

	XE_WARN_ON(err < 0);

	return err < 0 ? 0 : err;
}

static inline unsigned int
xe_eu_attentions_count(const struct prelim_xe_eu_attentions *a)
{
	return bitmap_weight((void *)a->att, a->size * BITS_PER_BYTE);
}

void prelim_xe_gt_eu_attentions_read(struct xe_gt *gt,
			      struct prelim_xe_eu_attentions *a,
			      const unsigned int settle_time_ms)
{
	unsigned int prev = 0;
	ktime_t end, now;

	now = ktime_get_raw();
	end = ktime_add_ms(now, settle_time_ms);

	a->ts = 0;
	a->size = min_t(int,
			prelim_xe_gt_eu_attention_bitmap_size(gt),
			sizeof(a->att));

	do {
		unsigned int attn;

		prelim_xe_gt_eu_attention_bitmap(gt, a->att, a->size);
		attn = xe_eu_attentions_count(a);

		now = ktime_get_raw();

		if (a->ts == 0)
			a->ts = now;
		else if (attn && attn != prev)
			a->ts = now;

		prev = attn;

		if (settle_time_ms)
			udelay(5);

		/*
		 * XXX We are gathering data for production SIP to find
		 * the upper limit of settle time. For now, we wait full
		 * timeout value regardless.
		 */
	} while (ktime_before(now, end));
}

unsigned int prelim_xe_eu_attentions_xor_count(const struct prelim_xe_eu_attentions *a,
					const struct prelim_xe_eu_attentions *b)
{
	unsigned int count = 0;
	unsigned int i;

	if (XE_WARN_ON(a->size != b->size))
		return -EINVAL;

	for (i = 0; i < a->size; i++)
		if (a->att[i] ^ b->att[i])
			count++;

	return count;
}

/* XXX: copy-paste from xe_guc_submit.c, find common define place */
#define GUC_ID_MAX		65535
static struct xe_exec_queue *
g2h_exec_queue_lookup(struct xe_guc *guc, u32 guc_id)
{
	struct xe_device *xe = guc_to_xe(guc);
	struct xe_exec_queue *q;

	if (unlikely(guc_id >= GUC_ID_MAX)) {
		drm_err(&xe->drm, "Invalid guc_id %u", guc_id);
		return NULL;
	}

	mutex_lock(&guc->submission_state.lock);
	q = xa_load(&guc->submission_state.exec_queue_lookup, guc_id);
	if (q)
		q = xe_exec_queue_get_unless_zero(q);
	mutex_unlock(&guc->submission_state.lock);
	if (unlikely(!q)) {
		drm_err(&xe->drm, "No engine present for guc_id %u", guc_id);
		return NULL;
	}

	xe_assert(xe, guc_id >= q->guc->id);
	xe_assert(xe, guc_id < (q->guc->id + q->width));

	return q;
}

#define NOTIFY_MSG_LEN_DW	1

static void notify_queue_advance_tail(struct notify_queue *notify_queue)
{
	lockdep_assert_held(&notify_queue->lock);

	notify_queue->tail = (notify_queue->tail + NOTIFY_MSG_LEN_DW) %
		EUDEBUG_QUEUE_NUM_DW;
}

static bool get_debug_notify(struct notify_queue *notify_queue, u32 *guc_id)
{
	bool ret = false;

	spin_lock_irq(&notify_queue->lock);
	if (notify_queue->tail != notify_queue->head) {
		*guc_id = notify_queue->data[notify_queue->tail];
		notify_queue_advance_tail(notify_queue);

		while (notify_queue->tail != notify_queue->head &&
		       notify_queue->data[notify_queue->tail] == *guc_id)
			notify_queue_advance_tail(notify_queue);

		ret = true;
	}
	spin_unlock_irq(&notify_queue->lock);

	return ret;
}

static bool notify_queue_full(struct notify_queue *notify_queue)
{
	lockdep_assert_held(&notify_queue->lock);

	return CIRC_SPACE(notify_queue->head, notify_queue->tail, EUDEBUG_QUEUE_NUM_DW) <=
		NOTIFY_MSG_LEN_DW;
}

int prelim_xe_guc_eu_kernel_debug_event_handler(struct xe_guc *guc, u32 *msg, u32 len)
{
	struct xe_gt *gt = guc_to_gt(guc);
	struct xe_device *xe = gt_to_xe(gt);
	struct notify_queue *notify_queue;
	unsigned long flags;
	bool full;

	BUILD_BUG_ON(EUDEBUG_QUEUE_NUM_DW % NOTIFY_MSG_LEN_DW);

	if (unlikely(len != 2)) {
		drm_err(&xe->drm, "Invalid length %u", len);
		return -EPROTO;
	}
	notify_queue = &gt->eudebug.notify_queue;

	spin_lock_irqsave(&notify_queue->lock, flags);
	full = notify_queue_full(notify_queue);
	if (!full) {
		memcpy(notify_queue->data + notify_queue->head, msg, sizeof(u32));
		notify_queue->head = (notify_queue->head + 1) % EUDEBUG_QUEUE_NUM_DW;
		queue_work(gt->eudebug.notify_wq, &notify_queue->worker);
		drm_dbg(&xe->drm, "Debug notify event!");
	} else {
		drm_warn(&xe->drm, "Debug notify queue full, shouldn't be possible!");
	}
	spin_unlock_irqrestore(&notify_queue->lock, flags);

	return full ? -ENOSPC : 0;
}

static void notify_queue_work_func(struct work_struct *w)
{
	struct notify_queue *notify_queue = container_of(w, struct notify_queue, worker);
	struct xe_gt *gt = notify_queue->gt;
	struct xe_device *xe = gt_to_xe(gt);
	struct xe_exec_queue *q;
	u32 guc_id, lrc_id;
	int ret;

	while (get_debug_notify(notify_queue, &guc_id)) {
		q = g2h_exec_queue_lookup(&gt->uc.guc, guc_id);
		if (unlikely(!q))
			continue;

		lrc_id = guc_id - q->guc->id;
		if (unlikely(lrc_id > q->width)) {
			drm_err(&xe->drm, "Invalid lrc_id %d", lrc_id);
			goto queue_put;
		}

		ret = prelim_xe_eudebug_sync_host(q, q->lrc[lrc_id]);
		if (ret)
			xe_exec_queue_kill(q);
queue_put:
		xe_exec_queue_put(q);
	}
}

int prelim_xe_gt_debug_init(struct xe_gt *gt)
{
	struct xe_device *xe = gt_to_xe(gt);

	if (!xe_device_eudebug_uses_guc(xe))
		return 0;

	gt->eudebug.notify_queue.gt = gt;
	spin_lock_init(&gt->eudebug.notify_queue.lock);
	INIT_WORK(&gt->eudebug.notify_queue.worker, notify_queue_work_func);

	gt->eudebug.notify_wq = alloc_workqueue("xe_gt_debug_notify_work_queue",
						WQ_UNBOUND | WQ_HIGHPRI, 0);
	if (!gt->eudebug.notify_wq)
		return -ENOMEM;

	return 0;
}

void prelim_xe_gt_debug_reset(struct xe_gt *gt)
{
	struct xe_device *xe = gt_to_xe(gt);

	if (!xe_device_eudebug_uses_guc(xe))
		return;

	spin_lock(&gt->eudebug.notify_queue.lock);
	gt->eudebug.notify_queue.head = 0;
	gt->eudebug.notify_queue.tail = 0;
	spin_unlock(&gt->eudebug.notify_queue.lock);
}
