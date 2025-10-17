// SPDX-License-Identifier: MIT
/*
 * Copyright © 2023 Intel Corporation
 */

#include <linux/delay.h>
#include "regs/xe_gt_regs.h"
#include "xe_device.h"
#include "xe_force_wake.h"
#include "xe_gt.h"
#include "xe_gt_topology.h"
#include "xe_gt_debug.h"
#include "xe_gt_mcr.h"
#include "xe_pm.h"
#include "xe_macros.h"

int prelim_xe_gt_foreach_dss_group_instance(struct xe_gt *gt,
				     int (*fn)(struct xe_gt *gt,
					       void *data,
					       u16 group,
					       u16 instance),
				     void *data)
{
	const enum xe_force_wake_domains fw_domains = XE_FW_GT;
	unsigned int dss, fw_ref;
	u16 group, instance;
	int ret = 0;

	fw_ref = xe_force_wake_get(gt_to_fw(gt), fw_domains);
	if (!fw_ref)
		return -ETIMEDOUT;

	for_each_dss_steering(dss, gt, group, instance) {
		ret = fn(gt, data, group, instance);
		if (ret)
			break;
	}

	xe_force_wake_put(gt_to_fw(gt), fw_ref);

	return ret;
}

static int read_first_attention_mcr(struct xe_gt *gt, void *data,
				    u16 group, u16 instance)
{
	unsigned int row;

	for (row = 0; row < 2; row++) {
		u32 val;

		val = xe_gt_mcr_unicast_read(gt, TD_ATT(row), group, instance);

		if (val)
			return 1;
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

	bitmap_or(dss_mask, gt->fuse_topo.c_dss_mask,
		  gt->fuse_topo.g_dss_mask, XE_MAX_DSS_FUSE_BITS);

	return  bitmap_weight(dss_mask, XE_MAX_DSS_FUSE_BITS) *
		PRELIM_TD_EU_ATTENTION_MAX_ROWS * MAX_THREADS *
		MAX_EUS_PER_ROW / 8;
}

struct attn_read_iter {
	struct xe_gt *gt;
	unsigned int i;
	unsigned int size;
	u8 *bits;
};

static int read_eu_attentions_mcr(struct xe_gt *gt, void *data,
				  u16 group, u16 instance)
{
	struct attn_read_iter * const iter = data;
	unsigned int row;

	for (row = 0; row < PRELIM_TD_EU_ATTENTION_MAX_ROWS; row++) {
		u32 val;

		if (iter->i >= iter->size)
			return 0;

		XE_WARN_ON(iter->i + sizeof(val) > prelim_xe_gt_eu_attention_bitmap_size(gt));

		val = xe_gt_mcr_unicast_read(gt, TD_ATT(row), group, instance);

		memcpy(&iter->bits[iter->i], &val, sizeof(val));
		iter->i += sizeof(val);
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
xe_eu_attentions_count(const struct xe_eu_attentions *a)
{
	return bitmap_weight((void *)a->att, a->size * BITS_PER_BYTE);
}

void prelim_xe_gt_eu_attentions_read(struct xe_gt *gt,
			      struct xe_eu_attentions *a,
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

unsigned int xe_eu_attentions_xor_count(const struct xe_eu_attentions *a,
					const struct xe_eu_attentions *b)
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
