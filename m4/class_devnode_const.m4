dnl #
dnl # struct class::devnode prototype changed across kernels
dnl # (const struct device *dev vs struct device *dev)
dnl #
AC_DEFUN([AC_CLASS_DEVNODE_CONST_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/kernel.h>
			#include <linux/build_bug.h>
			#include <linux/device/class.h>
		],[
			/*
			 * Fail compilation if struct class::devnode is NOT a const prototype.
			 * We then define a macro used to select the non-const callback.
			 */
			BUILD_BUG_ON(!__same_type(((struct class *)0)->devnode,
					       (char *(*)(const struct device *, umode_t *))0));
		],[
		],[
			AC_DEFINE([BPM_CLASS_DEVNODE_CONST_NOT_PRESENT], 1,
				[struct class::devnode does not take const struct device *])
		])
	])
])
