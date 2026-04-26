/* SPDX-License-Identifier: GPL-2.0 */
/*
 * workqueue.h --- work queue handling for Linux.
 */

#ifndef __BACKPORT_LINUX_WORKQUEUE_H
#define __BACKPORT_LINUX_WORKQUEUE_H
#include_next <linux/workqueue.h>

#ifdef BPM_ALLOC_ORDERED_WORKQUEUE_LOCKDEP_MAP_NOT_PRESENT

#define alloc_ordered_workqueue_lockdep_map(fmt, flags, lockdep_map, ...) \
		alloc_ordered_workqueue(fmt, flags)
#endif

#ifdef BPM_DISBALE_WORK_SYNC_NOT_PRESENT
#define disable_work_sync cancel_work_sync
#endif

#ifdef BPM_SYSTEM_PERCPU_WQ_NOT_PRESENT
#define system_percpu_wq system_wq
#endif

#endif /* __BACKPORT_LINUX_WORKQUEUE_H */
