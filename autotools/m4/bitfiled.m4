dnl #
dnl # v6.3-e2192de59e45
dnl # bitfield: add FIELD_PREP_CONST()
dnl #
AC_DEFUN([AC_FIELD_PREP_CONST_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <linux/bitfield.h>
                ], [
                        #ifdef FIELD_PREP_CONST
                        #error FIELD_PREP_CONST #defined
                        #endif
                ], [
                        AC_DEFINE(BPM_FIELD_PREP_CONST_NOT_PRESENT, 1,
                                [whether FIELD_PREP_CONST is defined])
                ])
        ])
])
