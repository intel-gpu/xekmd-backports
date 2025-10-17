dnl #
dnl # v6.13-b35108a51cf7
dnl # jiffies: Define secs_to_jiffies()
dnl #
AC_DEFUN([AC_SECS_TO_JIFFIES_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <linux/ktime.h>
                ],[
			secs_to_jiffies(1);
                ],[
		],[
                        AC_DEFINE(BPM_SECS_TO_JIFFIES_NOT_PRESENT, 1,
                                [secs_to_jiffies() function is not available])
                ])
        ])
])
