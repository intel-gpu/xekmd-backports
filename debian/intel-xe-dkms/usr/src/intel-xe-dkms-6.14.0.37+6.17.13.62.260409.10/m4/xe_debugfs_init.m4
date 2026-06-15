dnl #
dnl # v6.10-0b30d57acafc
dnl # drm/debugfs: rework debugfs directory creation v5
dnl #
AC_DEFUN([AC_DRM_MINOR_DEBUGFS_SYMLINK_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <linux/types.h>
                        #include <drm/drm_file.h>
                        #include <linux/debugfs.h>
                ],[
			struct drm_minor *minor = NULL;
                        (void)minor->debugfs_symlink;
                ],[
		],[
                        AC_DEFINE(BPM_DRM_MINOR_DEBUGFS_SYMLINK_NOT_PRESENT, 1,
                                [debugfs_symlink field not present in drm_minor, manual symlink creation needed])
                ])
        ])
])
