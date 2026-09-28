#ifndef __BACKPORT_PM_RUNTIME_H
#define __BACKPORT_PM_RUNTIME_H
#include_next <linux/pm_runtime.h>

#ifdef BPM_PM_RUNTIME_GET_IF_ACTIVE_ARG2_NOT_PRESENT
#define pm_runtime_get_if_active(x) pm_runtime_get_if_active(x,true)
#endif

#ifdef BPM_PM_RUNTIME_AUTOSUSPEND_MARK_LAST_BUSY_NOT_PRESENT
static inline int backport_pm_runtime_put_autosuspend(struct device *dev)
{
	pm_runtime_mark_last_busy(dev);
	return pm_runtime_put_autosuspend(dev);
}
#define pm_runtime_put_autosuspend backport_pm_runtime_put_autosuspend

static inline int backport_pm_runtime_put_sync_autosuspend(struct device *dev)
{
	pm_runtime_mark_last_busy(dev);
	return pm_runtime_put_sync_autosuspend(dev);
}
#define pm_runtime_put_sync_autosuspend backport_pm_runtime_put_sync_autosuspend

static inline int backport_pm_request_autosuspend(struct device *dev)
{
	pm_runtime_mark_last_busy(dev);
	return pm_request_autosuspend(dev);
}
#define pm_request_autosuspend backport_pm_request_autosuspend

static inline int backport_pm_runtime_autosuspend(struct device *dev)
{
	pm_runtime_mark_last_busy(dev);
	return pm_runtime_autosuspend(dev);
}
#define pm_runtime_autosuspend backport_pm_runtime_autosuspend
#endif

#endif /* __BACKPORT_PM_RUNTIME_H */
