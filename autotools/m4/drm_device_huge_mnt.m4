dnl #
dnl # v7.0-rc1 - ce6b66023369
dnl # drm/gem: Allocate shmfs backing storage in huge pages
dnl # Adds huge_mnt field to struct drm_device
dnl #
AC_DEFUN([AC_DRM_DEVICE_HUGE_MNT_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <drm/drm_device.h>
		],[
			struct drm_device test_dev;
			test_dev.huge_mnt = NULL;
		],[
		],[
			AC_DEFINE(BPM_DRM_DEVICE_HUGE_MNT_NOT_PRESENT, 1,
				[struct drm_device does not have huge_mnt member])
		])
	])
])
