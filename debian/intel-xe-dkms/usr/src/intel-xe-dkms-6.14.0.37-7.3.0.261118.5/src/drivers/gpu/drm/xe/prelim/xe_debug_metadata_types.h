/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2023 Intel Corporation
 */

#ifndef _XE_DEBUG_METADATA_TYPES_H_
#define _XE_DEBUG_METADATA_TYPES_H_

#include <linux/kref.h>

struct prelim_xe_debug_metadata {
	/** @type: type of given metadata */
	u64 type;

	/** @ptr: copy of userptr, given as a metadata payload */
	void *ptr;

	/** @len: length, in bytes of the metadata */
	u64 len;

	/** @ref: reference count */
	struct kref refcount;
};

#endif
