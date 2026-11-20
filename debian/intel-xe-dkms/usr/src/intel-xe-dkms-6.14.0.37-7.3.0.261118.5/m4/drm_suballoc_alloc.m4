dnl #
dnl # 16843e6638b7
dnl # drm/sa: Split drm_suballoc_new() into SA alloc and init helpers
dnl #

AC_DEFUN([AC_DRM_SUBALLOC_ALLOC_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <linux/slab.h>
                        #include <drm/drm_suballoc.h>
                ],[
                        (void)drm_suballoc_alloc(GFP_KERNEL);
                ],[
                ],[
                        AC_DEFINE(BPM_DRM_SUBALLOC_ALLOC_NOT_PRESENT, 1,
                                [drm_suballoc_alloc() not available])
                ])
        ])
])
