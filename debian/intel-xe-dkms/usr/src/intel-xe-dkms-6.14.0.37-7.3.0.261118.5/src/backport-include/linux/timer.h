#ifndef __BACKPORT_LINUX_TIMER_H
#define __BACKPORT_LINUX_TIMER_H

#include_next <linux/timer.h>

#ifdef BPM_TIMER_DELETE_NOT_PRESENT
#define timer_delete(_timer) del_timer_sync(_timer)
#endif

#endif /* __BACKPORT_LINUX_TIMER_H */
