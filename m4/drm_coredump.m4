dnl #
dnl # v6.16-fa4b8b3e3a11
dnl # drm/print: Add drm_coredump_printer_is_full
dnl #
AC_DEFUN([AC_DRM_COREDUMP_PRINTER_IS_FULL_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <drm/drm_print.h>
		],[
			drm_coredump_printer_is_full(NULL);
		],[
		],[
                        AC_DEFINE(BPM_DRM_COREDUMP_PRINTER_IS_FULL_NOT_PRESENT, 1,
                                [drm_coredump_printer_is_full function is not avilable])
                ])
        ])
])
