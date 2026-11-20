dnl #
dnl # v6.11-1d4ce389da2b
dnl # ice: add and use roundup_u64 instead of open coding equivalent
dnl #
AC_DEFUN([AC_DIV_U64_ROUND_UP_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <linux/math64.h>
                ],[
			DIV_U64_ROUND_UP(0, 0);
                ],[
		],[
                        AC_DEFINE(BPM_DIV_U64_ROUND_UP_NOT_PRESENT, 1,
                                [DIV_U64_ROUND_UP macro is not avilable])
                ])
        ])
])
