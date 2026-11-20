dnl #
dnl # v7.1.4.6 bca84a7b93fd
dnl # PM: sleep: Use DPM_FLAG_SMART_SUSPEND conditionally
dnl #
AC_DEFUN([AC_DEV_PM_SMART_SUSPEND_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
            #include <linux/device.h>
		], [
			bool (*fn)(struct device *) = dev_pm_smart_suspend;
			(void)fn;
		], [
		], [
			AC_DEFINE(BPM_DEV_PM_SMART_SUSPEND_NOT_PRESENT, 1,
			[dev_pm_smart_suspend is not available])
		])
	])
])
