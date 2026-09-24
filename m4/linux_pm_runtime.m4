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

dnl #
dnl # v6.17- 08071e64cb64
dnl # PM: runtime: Mark last busy stamp in pm_runtime_autosuspend()
dnl #
AC_DEFUN([AC_PM_RUNTIME_AUTOSUSPEND_MARK_LAST_BUSY_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <linux/types.h>
                        extern u64 bpm_probe_last_busy_marker(void) __attribute__((__error__("marks last_busy")));
                        #define ktime_get_mono_fast_ns bpm_probe_last_busy_marker
                        #include <linux/pm_runtime.h>
                        struct device *bpm_probe_dev;
                ],[
                        pm_runtime_put_autosuspend(bpm_probe_dev);
                ],[
                        AC_DEFINE(BPM_PM_RUNTIME_AUTOSUSPEND_MARK_LAST_BUSY_NOT_PRESENT, 1,
                                [pm_runtime_*autosuspend() helpers do not mark last_busy])
                ])
        ])
])
