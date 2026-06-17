// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 Intel
 *
 * Based on drivers/base/devres.c
 */

#include <drm/drm_managed.h>
#include <linux/mutex.h>

#ifdef BPM_DRMM_WORKQUEUE_RELEASE_NOT_PRESENT
void __drmm_workqueue_release(struct drm_device *device, void *res)
{
	struct workqueue_struct *wq = res;

	destroy_workqueue(wq);
}
EXPORT_SYMBOL(__drmm_workqueue_release);
#endif

#ifdef BPM_DRMM_MUTEX_INIT_NOT_PRESENT
void __drmm_mutex_release(struct drm_device *dev, void *res)
{
        struct mutex *lock = res;

        mutex_destroy(lock);
}
EXPORT_SYMBOL(__drmm_mutex_release);

#endif
