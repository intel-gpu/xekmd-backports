#ifndef __BACKPORT_DRM_GPU_SCHEDULER_H
#define __BACKPORT_DRM_GPU_SCHEDULER_H

#ifndef for_each_if
#define for_each_if(condition) if (!(condition)) {} else
#endif

#include_next <drm/gpu_scheduler.h>

#endif /* __BACKPORT_DRM_GPU_SCHEDULER_H */
