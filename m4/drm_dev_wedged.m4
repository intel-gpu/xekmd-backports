dnl #
dnl # v6.15-b7cf9f4ac1b8
dnl # drm: Introduce device wedged event
dnl #
AC_DEFUN([AC_DRM_DEV_WEDGED_EVENT_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <drm/drm_drv.h>
		],[
			(void)(&drm_dev_wedged_event);
		],[
		],[
			AC_DEFINE(BPM_DRM_DEV_WEDGED_EVENT_NOT_PRESENT, 1,
				[DRM_DEV_WEDGED_EVENT is not avilable])
		])
	])
])

dnl #
dnl # v6.17 - e41315787dda
dnl # drm: Add missing struct drm_wedge_task_info kernel doc
dnl #
AC_DEFUN([AC_DRM_WEDGE_TASK_INFO_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <drm/drm_device.h>
		],[
			struct drm_wedge_task_info info;
			(void)info;
		],[
		],[
			AC_DEFINE(BPM_DRM_WEDGE_TASK_INFO_NOT_PRESENT, 1,
				[struct drm_wedge_task_info is not avilable])
		])
	])
])

dnl #
dnl # v6.16-cd8f6f9afcb0
dnl # drm: Add optional guilty task info to drm_dev_wedged_event()
dnl #
AC_DEFUN([AC_DRM_DEV_WEDGED_EVENT_ARG3_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <drm/drm_drv.h>
                ],[
                        struct drm_device drm;
                        drm_dev_wedged_event(&drm, 0, NULL);
                ],[
                ],[
                        AC_DEFINE(BPM_DRM_DEV_WEDGED_EVENT_ARG3_NOT_PRESENT, 1,
                                [DRM_DEV_WEDGED_EVENT does not have 3rd argument])
                ])
        ])
])
