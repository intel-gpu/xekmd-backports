dnl #
dnl # v6.14-cb2e1c2136f7
dnl # drm: remove driver date from struct drm_driver and all drivers
dnl #
AC_DEFUN([AC_DRV_DATE_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <drm/drm_drv.h>
		],[
			struct drm_driver driver = {
				.name = "test",
				.desc = "test",
				.date = "20201103",
				.major = 1,
				.minor = 1,
				.patchlevel = 0,
			};
		],[
			AC_DEFINE(BPM_DRV_DATE_NOT_PRESENT, 1,
				[DRIVER_DATE field is not present or not needed in drm_driver structure])
		])
	])
])
