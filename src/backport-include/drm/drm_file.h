#ifndef __BACKPORT_DRM_FILE_H__
#define __BACKPORT_DRM_FILE_H__

#include_next <drm/drm_file.h>
#include <drm/drm_gem.h>

#ifdef BPM_DRM_MEMORY_STATS_NOT_PRESENT
struct drm_memory_stats {
	u64 shared;
	u64 private;
	u64 resident;
	u64 purgeable;
	u64 active;
};

static inline void drm_print_memory_stats(struct drm_printer *p,
					  const struct drm_memory_stats *stats,
					  enum drm_gem_object_status supported_status,
					  const char *region)
{
}

static inline int drm_memory_stats_is_zero(const struct drm_memory_stats *stats)
{
	return !stats->shared && !stats->private && !stats->resident &&
	       !stats->purgeable && !stats->active;
}

#endif /* BPM_DRM_MEMORY_STATS_NOT_PRESENT */
#endif /* __BACKPORT_DRM_FILE_H__ */
