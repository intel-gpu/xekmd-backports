dnl #
dnl # v6.17 - 6d3c3ca4c77e
dnl # module: Rename EXPORT_SYMBOL_GPL_FOR_MODULES to EXPORT_SYMBOL_FOR_MODULES
dnl #
AC_DEFUN([AC_EXPORT_SYMBOL_FOR_MODULES_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
			#include <linux/export.h>
		],[
			EXPORT_SYMBOL_FOR_MODULES(sym, mods);
		],[
		],[
			AC_DEFINE(BPM_EXPORT_SYMBOL_FOR_MODULES_NOT_PRESENT, 1,
				[EXPORT_SYMBOL_FOR_MODULES macro is not avilable])
		])
	])
])
