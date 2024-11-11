#ifndef __BACKPORT_PM_RUNTIME_H
#define __BACKPORT_PM_RUNTIME_H
#include_next <linux/pm_runtime.h>

#ifdef BPM_PM_RUNTIME_GET_IF_ACTIVE_ARG2_NOT_PRESENT
#define pm_runtime_get_if_active(x) pm_runtime_get_if_active(x,true)
#endif

#endif /* __BACKPORT_PM_RUNTIME_H */
