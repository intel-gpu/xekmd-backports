/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2025 Intel Corporation
 */

#ifndef __XE_GT_DEBUG_TYPES_
#define __XE_GT_DEBUG_TYPES_

#include <linux/types.h>

#define XE_GT_EU_ATT_ROWS 2u
#define XE_GT_EU_ATT_MAX_THREADS 16
#define XE_GT_EU_MAX_NUM  1024

struct prelim_xe_eu_attentions {
	u8 att[XE_GT_EU_MAX_NUM *
	       XE_GT_EU_ATT_ROWS *
	       XE_GT_EU_ATT_MAX_THREADS/8];
	unsigned int size;
};

#endif
