dnl #
dnl # v6.15-c367b772e6d8
dnl # drm/managed: Add DRM-managed alloc_ordered_workqueue
dnl #
AC_DEFUN([AC_DRMM_WORKQUEUE_RELEASE_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <drm/drm_managed.h>
		],[
			__drmm_workqueue_release(NULL, NULL);
		],[
		],[
                        AC_DEFINE(BPM_DRMM_WORKQUEUE_RELEASE_NOT_PRESENT, 1,
                                [__drmm_workqueue_release is not available])
                ])
        ])
])
dnl #
dnl # v6.15-c367b772e6d8
dnl # drm/managed: Add DRM-managed alloc_ordered_workqueue
dnl #
AC_DEFUN([AC_DRMM_ALLOC_ORDERED_WORKQUEUE_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <drm/drm_managed.h>
                ],[
                        drmm_alloc_ordered_workqueue(NULL, "test", 0);
                ],[
                ],[
                        AC_DEFINE(BPM_DRMM_ALLOC_ORDERED_WORKQUEUE_NOT_PRESENT, 1,
                                [drmm_alloc_ordered_workqueue is not available])
                ])
        ])
])
