dnl #
dnl # Detect kernels where unbound parent bridge should disable PM
dnl #
AC_DEFUN([AC_XE_PM_UNBOUNDED_BRIDGE_DISABLE_PM], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/version.h>
		],[
			#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0)
			#error "Use debug-only unbound-bridge PM messaging on older kernels"
			#endif
		],[
			AC_DEFINE([BPM_XE_PM_UNBOUNDED_BRIDGE_DISABLE_PM], 1,
				[Unbound parent PCI bridge should disable PM and emit warning])
		])
	])
])
