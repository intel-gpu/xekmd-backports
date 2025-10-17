dnl #
dnl # v6.8-05d249352f1a
dnl # drm/exec: Pass in initial # of objects
dnl #
AC_DEFUN([AC_DRM_EXEC_INIT_ARG3_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <drm/drm_exec.h>
                ],[
			struct drm_exec exec;
			drm_exec_init(&exec, 0, 0);
			return 0;
		],[
		],[
                        AC_DEFINE(BPM_DRM_EXEC_INIT_ARG3_NOT_PRESENT, 1,
                                [drm_exec_init() takes only 2 arguments])
                ])
        ])
])
