dnl #
dnl # v6.5-3f09a0cd4ea3
dnl # drm: Add common fdinfo helper
dnl #
AC_DEFUN([AC_DRM_SHOW_FDINFO_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <drm/drm_file.h>
                        #include <drm/drm_drv.h>
                ],[
                        struct drm_driver driver = {
                                .show_fdinfo = NULL,
                        };

                        drm_show_fdinfo(NULL, NULL);
                ],[
                ],[
                        AC_DEFINE(BPM_DRM_SHOW_FDINFO_NOT_PRESENT, 1,
                                [drm show_fdinfo support is not available])
                ])
        ])
])

dnl #
dnl # v6.5-686b21b5f6ca2
dnl # drm: Add fdinfo memory stats
dnl #
AC_DEFUN([AC_DRM_MEMORY_STATS_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <drm/drm_file.h>
                ],[
                        struct drm_memory_stats stats[TTM_NUM_MEM_TYPES] = {};

                        drm_print_memory_stats(NULL, &stats[0],
                                               DRM_GEM_OBJECT_ACTIVE,
                                               NULL);
                ],[
                ],[
                        AC_DEFINE(BPM_DRM_MEMORY_STATS_NOT_PRESENT, 1,
                                [drm_memory_stats is not available])
                ])
        ])
])
