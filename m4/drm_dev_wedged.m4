dnl #
dnl # v6.15-b7cf9f4ac1b8
dnl # drm: Introduce device wedged event
dnl #
AC_DEFUN([AC_DRM_DEV_WEDGED_EVENT_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <drm/drm_drv.h>
		],[
			struct drm_device drm;
			drm_dev_wedged_event(&drm, 0, NULL);
		],[
		],[
			AC_DEFINE(BPM_DRM_DEV_WEDGED_EVENT_NOT_PRESENT, 1,
				[DRM_DEV_WEDGED_EVENT is not avilable])
		])
	])
])
