#ifndef __BACKPORT_DRM_FILE_H__
#define __BACKPORT_DRM_FILE_H__

#include_next <drm/drm_file.h>
#include <drm/drm_gem.h>

#ifdef BPM_DRM_MEMORY_STATS_NOT_PRESENT
#include <drm/drm_print.h>
#include <linux/math64.h>
#include <linux/sizes.h>

struct drm_memory_stats {
	u64 shared;
	u64 private;
	u64 resident;
	u64 purgeable;
	u64 active;
};

static inline void bpm_drm_fdinfo_print_size(struct drm_printer *p,
					     const char *stat,
					     const char *region, u64 size)
{
	const char *units[] = { "", " KiB", " MiB" };
	unsigned int unit;

	for (unit = 0; unit < ARRAY_SIZE(units) - 1; unit++) {
		if (!size || !IS_ALIGNED(size, SZ_1K))
			break;
		size = div_u64(size, SZ_1K);
	}

	drm_printf(p, "drm-%s-%s:\t%llu%s\n", stat, region, size, units[unit]);
}

static inline void drm_print_memory_stats(struct drm_printer *p,
					  const struct drm_memory_stats *stats,
					  enum drm_gem_object_status supported_status,
					  const char *region)
{
	bpm_drm_fdinfo_print_size(p, "total", region, stats->private + stats->shared);
	bpm_drm_fdinfo_print_size(p, "shared", region, stats->shared);
	if (supported_status & DRM_GEM_OBJECT_ACTIVE)
		bpm_drm_fdinfo_print_size(p, "active", region, stats->active);
	if (supported_status & DRM_GEM_OBJECT_RESIDENT)
		bpm_drm_fdinfo_print_size(p, "resident", region, stats->resident);
	if (supported_status & DRM_GEM_OBJECT_PURGEABLE)
		bpm_drm_fdinfo_print_size(p, "purgeable", region, stats->purgeable);
}

static inline int drm_memory_stats_is_zero(const struct drm_memory_stats *stats)
{
	return !stats->shared && !stats->private && !stats->resident &&
	       !stats->purgeable && !stats->active;
}

#endif /* BPM_DRM_MEMORY_STATS_NOT_PRESENT */
#endif /* __BACKPORT_DRM_FILE_H__ */
