/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BACKPORT_LINUX_JIFFIES_H
#define __BACKPORT_LINUX_JIFFIES_H

#include_next <linux/jiffies.h>
#include <linux/ktime.h>

#ifdef BPM_SECS_TO_JIFFIES_NOT_PRESENT
#define secs_to_jiffies(_secs) msecs_to_jiffies((_secs) * 1000)
#endif

#endif /* __BACKPORT_LINUX_JIFFIES_H */
