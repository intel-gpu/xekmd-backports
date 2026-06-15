dnl #
dnl # v6.9-c0ef3df8dbaef
dnl # PM: runtime: Simplify pm_runtime_get_if_active() usage
dnl #
AC_DEFUN([AC_PM_RUNTIME_GET_IF_ACTIVE_ARG2_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <linux/pm_runtime.h>
                ],[
			pm_runtime_get_if_active(NULL,0);
		],[
                        AC_DEFINE(BPM_PM_RUNTIME_GET_IF_ACTIVE_ARG2_NOT_PRESENT, 1,
                                [pm_runtime_get_if_active() does not have 2nd Arugment  not available])
                ])
        ])
])
