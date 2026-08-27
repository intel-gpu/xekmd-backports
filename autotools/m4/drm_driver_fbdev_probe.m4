dnl #
dnl # v6.12 - 5d08c44e47b9
dnl # drm/fbdev: Add memory-agnostic fbdev client
dnl #
AC_DEFUN([AC_DRM_DRIVER_FBDEV_PROBE_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <drm/drm_drv.h>
		],[
			struct drm_driver drv = {
				.fbdev_probe = NULL,
			};
			(void)drv;
		],[
		],[
			AC_DEFINE(BPM_DRM_DRIVER_FBDEV_PROBE_NOT_PRESENT, 1,
				[struct drm_driver .fbdev_probe member is not present])
		])
	])
])
