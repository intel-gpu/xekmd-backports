dnl #
dnl # v6.16-34a364ff04e9
dnl # PM: sleep: Introduce pm_suspend_in_progress()
dnl #
AC_DEFUN([AC_PM_SUSPEND_IN_PROGRESS_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <linux/suspend.h>
		],[
			pm_suspend_in_progress();
		],[
		],[
                        AC_DEFINE(BPM_PM_SUSPEND_IN_PROGRESS_NOT_PRESENT, 1,
                                [PM_SUSPEND_IN_PROGRESS function is not avilable])
                ])
        ])
])
