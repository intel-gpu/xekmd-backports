dnl #
dnl # v6.9-e7835e023f84
dnl # drm/xe: switch from drm_debug_printer() to device specific drm_dbg_printer()
dnl #
AC_DEFUN([AC_DRM_DBG_PRINTER_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <drm/drm_print.h>
                ],[
                        drm_debug_printer(NULL);
                ],[
                        AC_DEFINE(BPM_DRM_DBG_PRINTER_NOT_PRESENT, 1,
                                [drm_dbg_printer() not available])
                ])
        ])
])

dnl #
dnl # v6.13-754e707e20e4
dnl # drm/print: Introduce drm_line_printer
dnl #
AC_DEFUN([AC_DRM_LINE_PRINTER_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <drm/drm_print.h>
                ],[
                        drm_line_printer(NULL,NULL,0);
		],[
                ],[
                        AC_DEFINE(BPM_DRM_LINE_PRINTER_NOT_PRESENT, 1,
                                [drm_line_printer() not available])
                ])
        ])
])
