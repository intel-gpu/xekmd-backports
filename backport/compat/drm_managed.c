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
static void drmm_mutex_release(struct drm_device *dev, void *res)
{
        struct mutex *lock = res;

        mutex_destroy(lock);
}

/**
 * drmm_mutex_init - &drm_device-managed mutex_init()
 * @dev: DRM device
 * @lock: lock to be initialized
 *
 * Returns:
 * 0 on success, or a negative errno code otherwise.
 *
 * This is a &drm_device-managed version of mutex_init(). The initialized
 * lock is automatically destroyed on the final drm_dev_put().
 */
int drmm_mutex_init(struct drm_device *dev, struct mutex *lock)
{
        mutex_init(lock);

        return drmm_add_action_or_reset(dev, drmm_mutex_release, lock);
}
EXPORT_SYMBOL(drmm_mutex_init);
#endif
