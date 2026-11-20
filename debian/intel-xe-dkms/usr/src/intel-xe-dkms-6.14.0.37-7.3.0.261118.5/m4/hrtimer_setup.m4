dnl #
dnl # v6.13-908a1d775422
dnl # hrtimers: Introduce hrtimer_setup() to replace hrtimer_init()
dnl #
AC_DEFUN([AC_HRTIMER_SETUP_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <linux/hrtimer.h>
                ],[
			hrtimer_setup(NULL, NULL, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
		],[
		],[
                        AC_DEFINE(BPM_HRTIMER_SETUP_NOT_PRESENT, 1,
                                [HRTIMER_SETUP macro is not avilable])
                ])
        ])
])
