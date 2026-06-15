// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 Intel
 *
 * Based on drivers/base/devres.c
 */

#include <drm/drm_managed.h>

#ifdef BPM_DRMM_WORKQUEUE_RELEASE_NOT_PRESENT
void __drmm_workqueue_release(struct drm_device *device, void *res)
{
	struct workqueue_struct *wq = res;

	destroy_workqueue(wq);
}
EXPORT_SYMBOL(__drmm_workqueue_release);
#endif
