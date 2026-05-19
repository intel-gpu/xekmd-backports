dnl #
dnl # v7.0 - DEFINE_GUARD_COND 4-arg form, ACQUIRE/ACQUIRE_ERR macros
dnl #
AC_DEFUN([AC_CLEANUP_ACQUIRE_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <linux/cleanup.h>
                ],[
                        #ifndef ACQUIRE
                        #error ACQUIRE not defined
                        #endif
                ],[
                ],[
                        AC_DEFINE(BPM_CLEANUP_ACQUIRE_NOT_PRESENT, 1,
                                [ACQUIRE/ACQUIRE_ERR/4-arg DEFINE_GUARD_COND not available])
                ])
        ])
])
