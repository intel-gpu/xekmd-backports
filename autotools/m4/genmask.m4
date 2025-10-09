dnl #
dnl # v6.16-19408200c094
dnl # bits: introduce fixed-type GENMASK_U*()
dnl #
AC_DEFUN([AC_GENMASK_U32_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <linux/bits.h>
                ],[
                        GENMASK_U32(0, 0);
                ],[
		],[
                        AC_DEFINE([BPM_GENMASK_U32_NOT_PRESENT], 1,
                                [GENMASK_U32 macro is not avilable])
                ])
        ])
])
