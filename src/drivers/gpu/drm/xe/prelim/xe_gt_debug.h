/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2023 Intel Corporation
 */

#ifndef __XE_GT_DEBUG_
#define __XE_GT_DEBUG_

#include <linux/bits.h>
#include <linux/math.h>

struct xe_gt;

#define PRELIM_XE_GT_ATTENTION_TIMEOUT_MS 100
#define XE_GT_EU_ATT_ROWS 2u

struct xe_eu_attentions {
#define XE_MAX_EUS 1024
#define XE_MAX_THREADS 10

	u8 att[DIV_ROUND_UP(XE_MAX_EUS * XE_MAX_THREADS, BITS_PER_BYTE)];
	unsigned int size;
	ktime_t ts;
};

unsigned int xe_gt_eu_att_regs(struct xe_gt *gt);

int prelim_xe_gt_eu_threads_needing_attention(struct xe_gt *gt);
int prelim_xe_gt_foreach_dss_group_instance(struct xe_gt *gt,
				     int (*fn)(struct xe_gt *gt,
					       void *data,
					       u16 group,
					       u16 instance,
					       bool present),
				     void *data);

int prelim_xe_gt_eu_attention_bitmap_size(struct xe_gt *gt);
int prelim_xe_gt_eu_attention_bitmap(struct xe_gt *gt, u8 *bits,
			      unsigned int bitmap_size);

void prelim_xe_gt_eu_attentions_read(struct xe_gt *gt,
			      struct xe_eu_attentions *a,
			      const unsigned int settle_time_ms);

unsigned int xe_eu_attentions_xor_count(const struct xe_eu_attentions *a,
					const struct xe_eu_attentions *b);
#endif
