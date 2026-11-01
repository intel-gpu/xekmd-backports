/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BACKPORT_LINUX_PERF_EVENT_H
#define __BACKPORT_LINUX_PERF_EVENT_H

#include <linux/errno.h>
#include_next <linux/perf_event.h>

#ifdef BPM_PERF_ALLOW_CPU_NOT_PRESENT
static inline int backport_perf_allow_cpu(void)
{
	if (!perfmon_capable())
		return -EACCES;

#ifdef CONFIG_PERF_EVENTS
#ifdef BPM_PERF_ALLOW_KERNEL_NOT_EXPORTED
	/* Do not bypass the perf LSM check when it is unavailable to modules. */
	return -EOPNOTSUPP;
#else
#ifdef BPM_PERF_ALLOW_KERNEL_NO_ARGS_NOT_PRESENT
	{
		struct perf_event_attr attr = {
			.type = PERF_TYPE_HARDWARE,
			.size = sizeof(attr),
		};

		return perf_allow_kernel(&attr);
	}
#else
	return perf_allow_kernel();
#endif
#endif
#else
	return 0;
#endif
}

#define perf_allow_cpu() backport_perf_allow_cpu()
#endif

#endif /* __BACKPORT_LINUX_PERF_EVENT_H */
