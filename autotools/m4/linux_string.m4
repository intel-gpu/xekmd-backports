dnl #
dnl # v6.9-e6584c3964f2f
dnl # string: Allow 2-argument strscpy()
dnl #
AC_DEFUN([AC_STRSCPY_ARG3_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <linux/string.h>
                ],[
                        strscpy(NULL, NULL);
                ],[
		],[
                        AC_DEFINE(BPM_STRSCPY_ARG3_PRESENT, 1,
                                [strscpy() argument3 is not available])
                ])
        ])
])
