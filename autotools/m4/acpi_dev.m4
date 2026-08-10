dnl #
dnl # v5.19-cf6ba0750a22
dnl # ACPI: bus: Introduce acpi_dev_for_each_child()
dnl #
AC_DEFUN([AC_ACPI_DEV_FOR_EACH_CHILD_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/acpi.h>
		], [
			acpi_dev_for_each_child(NULL, NULL, NULL);
		], [
		], [
			AC_DEFINE([BPM_ACPI_DEV_FOR_EACH_CHILD_NOT_PRESENT], 1,
				[acpi_dev_for_each_child() is not available])
		])
	])
])
