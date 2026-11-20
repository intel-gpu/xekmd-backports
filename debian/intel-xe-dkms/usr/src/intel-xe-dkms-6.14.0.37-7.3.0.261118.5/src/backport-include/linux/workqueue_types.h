/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BACKPORT_WORKQUEUE_TYPES_H
#define __BACKPORT_WORKQUEUE_TYPES_H


#ifdef HAVE_LINUX_WORKQUEUE_TYPES_H
#include_next <linux/workqueue_types.h>
#else
#include <linux/workqueue.h>
#endif

#endif /* __BACKPORT_WORKQUEUE_TYPES_H */
