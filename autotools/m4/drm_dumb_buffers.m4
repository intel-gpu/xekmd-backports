dnl #
dnl # v7.0 - fb24aaf5415c
dnl # drm/dumb-buffers: Provide helper to set pitch and size
dnl #
AC_DEFUN([AC_DRM_MODE_SIZE_DUMB_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#define DRM_FORMAT_INVALID	0
			#include <drm/drm_dumb_buffers.h>
		],[
			struct drm_device *dev = NULL;
			struct drm_mode_create_dumb *args = NULL;
			drm_mode_size_dumb(dev, args, 0, 0);
		],[
			AC_DEFINE(BPM_DRM_MODE_SIZE_DUMB_PRESENT, 1,
				[drm_mode_size_dumb() is available, kernel >= 7.0])
		],[
			AC_DEFINE(BPM_DRM_MODE_SIZE_DUMB_NOT_PRESENT, 1,
				[drm_mode_size_dumb() is not available, kernel < 7.0])
		])
	])
])

