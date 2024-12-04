dnl #
dnl # v6.10-96950929eb23
dnl # drm/buddy: Implement tracking clear page feature
dnl #
AC_DEFUN([AC_DRM_BUDDY_FREE_LIST_ARG3_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <drm/drm_buddy.h>
                ],[
                        drm_buddy_free_list(NULL,NULL);
                ],[
                        AC_DEFINE(BPM_DRM_BUDDY_FREE_LIST_ARG3_NOT_PRESENT, 1,
                                [drm_buddy_free_list() does not have 3rd Arugment  not available])
                ])
        ])
])
