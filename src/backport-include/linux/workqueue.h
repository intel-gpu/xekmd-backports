/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __BACKPORT_LINUX_WORKQUEUE_H
#define __BACKPORT_LINUX_WORKQUEUE_H
#include_next <linux/workqueue.h>

#ifdef BPM_ALLOC_ORDERED_WORKQUEUE_LOCKDEP_MAP_NOT_PRESENT

#define alloc_ordered_workqueue_lockdep_map(fmt, flags, lockdep_map, ...) \
		alloc_ordered_workqueue(fmt, flags)
#endif

#endif /* __BACKPORT_LINUX_WORKQUEUE_H */
