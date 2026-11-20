/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BACKPORT_SUSPEND_H
#define __BACKPORT_SUSPEND_H

#include_next<linux/suspend.h>

#ifdef BPM_PM_SUSPEND_IN_PROGRESS_NOT_PRESENT
static inline bool pm_suspend_in_progress(void)
{
	return pm_suspend_target_state != PM_SUSPEND_ON;
}
#endif

#endif /* __BACKPORT_SUSPEND_H */
