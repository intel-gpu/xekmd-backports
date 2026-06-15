dnl #
dnl # v6.12-641bb4394f405 
dnl # fs: move FMODE_UNSIGNED_OFFSET to fop_flags
dnl #
AC_DEFUN([AC_FOP_UNSIGNED_OFFSET_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <linux/fs.h>
                ], [
                        #ifdef FOP_UNSIGNED_OFFSET
                        #error FOP_UNSIGNED_OFFSET #defined
                        #endif
                ], [
                        AC_DEFINE(BPM_FOP_UNSIGNED_OFFSET_NOT_PRESENT, 1,
                                [whether FOP_UNSIGNED_OFFSET is defined])
                ])
        ])
])
