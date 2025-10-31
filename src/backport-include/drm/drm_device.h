#ifndef __BACKPORT_DRM_DEVICE_H_
#define __BACKPORT_DRM_DEVICE_H_

#include_next<drm/drm_device.h>

#ifdef BPM_DRM_DEV_WEDGED_EVENT_NOT_PRESENT

/*
 * Recovery methods for wedged device in order of less to more side-effects.
 * To be used with drm_dev_wedged_event() as recovery @method. Callers can
 * use any one, multiple (or'd) or none depending on their needs.
 */
#define DRM_WEDGE_RECOVERY_NONE         BIT(0)  /* optional telemetry collection */
#define DRM_WEDGE_RECOVERY_REBIND       BIT(1)  /* unbind + bind driver */
#define DRM_WEDGE_RECOVERY_BUS_RESET    BIT(2)  /* unbind + reset bus device + bind */

/**
 * struct drm_wedge_task_info - information about the guilty task of a wedge dev
 */
struct drm_wedge_task_info {
	/** @pid: pid of the task */
	pid_t pid;
	/** @comm: command name of the task */
	char comm[TASK_COMM_LEN];
};
#endif

#endif
