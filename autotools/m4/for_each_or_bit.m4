dnl #
dnl # v6.3-1470afefc3c42
dnl # cpumask: introduce for_each_cpu_or
dnl #
AC_DEFUN([AC_FOR_EACH_OR_BIT_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <linux/find.h>
                ],[
                        unsigned long bit;

                        for_each_or_bit(bit, NULL, NULL, 0);
                ],[
                ],[
                        AC_DEFINE(BPM_FOR_EACH_OR_BIT_NOT_PRESENT, 1,
                                [for_each_or_bit is not available])
                ])
        ])
])
