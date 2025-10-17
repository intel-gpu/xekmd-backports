/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2023 Intel Corporation
 */

#ifndef __XE_GT_DEBUG_
#define __XE_GT_DEBUG_

#define PRELIM_TD_EU_ATTENTION_MAX_ROWS 2u

#include "xe_gt_types.h"

#define PRELIM_XE_GT_ATTENTION_TIMEOUT_MS 100

struct xe_eu_attentions {
#define PRELIM_XE_MAX_EUS 1024
#define PRELIM_XE_MAX_THREADS 10

	u8 att[DIV_ROUND_UP(PRELIM_XE_MAX_EUS * PRELIM_XE_MAX_THREADS, BITS_PER_BYTE)];
	unsigned int size;
	ktime_t ts;
};

int prelim_xe_gt_eu_threads_needing_attention(struct xe_gt *gt);
int prelim_xe_gt_foreach_dss_group_instance(struct xe_gt *gt,
				     int (*fn)(struct xe_gt *gt,
					       void *data,
					       u16 group,
					       u16 instance),
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
