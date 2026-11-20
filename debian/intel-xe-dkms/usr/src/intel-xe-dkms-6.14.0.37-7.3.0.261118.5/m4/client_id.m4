dnl #
dnl # v6.5-3f09a0cd4ea3
dnl # drm: Add common fdinfo helper
dnl #
AC_DEFUN([AC_DRM_FILE_CLIENT_ID_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <drm/drm_file.h>
                ],[
                        struct drm_file *file = NULL;

                        (void)file->client_id;
                ],[
                ],[
                        AC_DEFINE(BPM_DRM_FILE_CLIENT_ID_NOT_PRESENT, 1,
                                [client_id field is not present in struct drm_file])
                ])
        ])
])
